# `pqchat-core`: the PqChat client core above `scaas-sdk` — build plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-17):** plan, not executed; nothing is built from it. Spec:
[`2026-11-17-pqchat-core.md`](../specs/2026-11-17-pqchat-core.md) (SPECIFIED, revision 2: Fable's review applied, its §14; open
points O1–O12, the coordinator's call on O1 and the controller's on O12 applied). Rules:
[clients/pqchat-core.md](../../clients/pqchat-core.md) CLI-PQC-01 to CLI-PQC-14, records CLI-PQC-30 and CLI-PQC-31. Protocol: the
UA-7 spec (P1–P49), the topics spec (P33–P46), [contracts/pqchat.md](../../contracts/pqchat.md). UNAUDITED.

**When it runs:** after the SDK's app-core surface exists: the SDK plan's T21 (`app_core`, on branch `scaas-sdk`), with its T3
(bindings spike) and T10 (operations) done before it. T0 and T2 may start as soon as the SDK crate skeleton (SDK T1) exists; every
task that calls a key, signing or read row of the spec's §5 waits for T1 here. Branch `pqchat-core`, worktree
`.claude/worktrees/pqchat-core`, rebased onto `scaas-sdk` once SDK T21 lands there. Merges on the owner's word only (merge
commits; `main` is PR-only).

**Goal:** `clients/pqchat-core` exists; it reproduces every PqChat vector row that crosses the SDK boundary; it creates, accepts,
rekeys, removes, leaves, sends and reads 1:1 and group sessions over a Matrix room and chain stores, recovers on a fresh device from
contract state alone and reads and writes public topics, with key handles only, PqChat records signed only by the SDK's PqChat
entries and every key- or epoch-choosing read trusted; and a real-crypto end-to-end run passes on a local chain and a local
homeserver, every decryption and verification check with a mutant that its own fixture reaches, killed by that check's reason.

**Commits:** one or more per task, `pqchat-core T<n>: <what>`, staged by explicit path, in this shared worktree with
`git commit --only -- <paths>`, with the session's attribution lines; no `Signed-off-by`. **No push, no merge.** No commit holding
only `TODO.md`.

## Global constraints (read before every task)

- AGENTS.md: `cargo`, `forge`, `anvil`, `npm` through `scripts/capped`, **foreground**, never inside `timeout`, never in the
  background; no `sleep` / `until` / `pgrep -f` loops; no background shell or `anvil` left behind (tests start and stop their own).
  **Docker bypasses `capped`:** the homeserver container runs with `--memory 1g --cpus 1`, one at a time, removed by the test's
  teardown. Never the live testnet stack, its containers or its RPC port (T13 runs only on the owner's word, at the next reset).
- **Every test `anvil` starts with `--enable-tx-gas-limit`** (anvil 1.8.5: "the transaction gas limit check as imposed by
  EIP-7825"), and each run that uses one first sends a positive control: a transaction above 2^24 gas, refused by the chain. The
  harness also refuses to send any transaction with a gas limit above 2^24, as a second line. Whether anvil meters state gas as
  Nethermind does is not assumed: T13 answers it.
- Local only: in-process fakes on `127.0.0.1:0`, `anvil`, a local Nethermind only where a precompile is needed (T11), a local
  homeserver in Docker. Inputs as real directories in this worktree (`smartcontracts/evm/lib` via `scripts/evm_libs.sh install`
  then `check`; `clients/clientkeys/node_modules`).
- TDD in every task: write the test, run it, **see it fail for the stated reason**, implement, run it green. Every negative test has
  its positive control beside it and changes one thing. **A negative of a check asserts the drop reason** (CLI-PQC-07's per-reason
  count), not only "not shown". Each task's mutants (listed) must each turn a named test red **for its own reason**, through a fixture
  that reaches the check with no other check in front of it, one at a time, through
  `clients/pqchat-core/runs/2026-11-17-pqchat-core-t<n>-mutants.py` (a list of `(file, old, new, test command)`, modes `run` and
  `check`, the SDK plan's form); record `…-t<n>-mutants.txt` committed (last line `N mutants, N killed, 0 survived, 0 not loaded`).
- **No cryptography in `clients/pqchat-core`** (CLI-PQC-01): no KEM, KDF, MAC, AEAD, signature, hash, padding, canonical JSON or
  decoder of a signed or encrypted byte format. A task that needs one adds the row to the SDK and `ua-rs` (T1), clientkeys rows first
  if the row is new. No key byte crosses into the crate (CLI-PQC-03): a step that cannot be done on handles stops the task and is
  reported (the app core would stay inside the SDK, the SDK spec's App cores section).
- PqChat records are signed only through the SDK's PqChat entries (CLI-PQC-04); no call in the crate takes or passes a digest or a
  byte string of its own to be signed (a doc test and a grep step).
- Every read that chooses a key, a recipient or an epoch, or feeds a decryption, is a trusted read (CLI-PQC-13): a grep step lists
  every read call in the crate with its mark, and the list is held equal to the spec's §5 R2.
- Byte formats change everywhere at once: vectors regenerated by `clients/clientkeys/scripts/pqchat-vectors.mjs`, never edited by
  hand; the crate reads them, writes none.
- Every outside input bounded by length and depth (Matrix events, stored payloads, record blobs, views' pages); no secret, handle,
  ciphertext, room id or Matrix id in an error, event, `Debug` or `tracing` line; `clippy::{unwrap_used, expect_used, panic,
  indexing_slicing}` denied in `src/`.
- No-reaction rule (CLI-PQC-07, CLI-PQC-08): every negative test also asserts zero writes and zero network calls caused by it,
  through recording fakes of the SDK's submission and of the Matrix transport.
- Writes an honest client refuses (a removed member's rekey, a forged message, a record in an unlisted instance) are made only by
  the **hostile harness** (`clients/pqchat-core/tests/hostile/`, on the SDK's vectors build and raw calldata), never by
  `pqchat-core`.
- Never edit a pin, a bound or a test to go green; a red stops the task and is reported with its output.
- New source files carry `// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0`. Code, comments, commits in English. No
  consumer-specific name in the crate. No absolute or temporary-directory path in a committed file; temp dirs by `mktemp -d` at run
  time.
- Gate logs: `clients/pqchat-core/runs/2026-11-17-pqchat-core-<step>.log` (git-ignored by `*.log`; first line `# <step> at commit
  <sha>`, last `rc=<n>`), progress lines on stdout (start, ok N/M, FAIL, a heartbeat every ~30 s; addresses, UAs and transaction
  hashes allowed, never keys). Only `clients/pqchat-core/runs/2026-11-17-pqchat-core-summary.txt` (`step | commit | rc | counts`) is
  committed. On resume read the logs and the summary first; a step done at the same commit on a clean tree is skipped.

## Gate steps

`clients/pqchat-core/runs/2026-11-17-pqchat-core-gates.sh [--only <step>]`, written in T0:

| Step | Command (each through `scripts/capped` where heavy) |
|---|---|
| `pqc-test` | `cargo test` in `clients/pqchat-core` |
| `pqc-clippy` | `cargo clippy --all-targets -- -D warnings` |
| `pqc-deny` | `cargo deny check`, `cargo audit` |
| `pqc-tree` | `cargo tree -e normal` holds no `scaas-ua`, `scaas-rpc`, `matrix-sdk`; `cargo tree -e features` one PQZ set |
| `pqc-reads` | the read-mark list (every read call and its mark) equal to the spec's §5 R1 / R2 |
| `pqc-wasm` | `cargo check --target wasm32-unknown-unknown` |
| `pqc-vectors` | the vector tests only (T3) |
| `sdk-test` | the SDK's tests with its `app-core` and `pqchat-records` features (T1's rows) |
| `ua-test` | `ua-rs`'s tests for T1's rows (`--features wallet,vectors`) |
| `ck-test` | `npm test` in `clients/clientkeys` (new rows first) |
| `pqc-chain` | the anvil tests (T5–T10), each starting its own `anvil --enable-tx-gas-limit` with the positive control |
| `pqc-e2e` | `cargo test --test e2e -- --ignored --test-threads 1` (T11) |
| `bind` | the SDK's generators over the reference library with `pqchat-core` linked (T12) |
| `docs` | `python3 scripts/docs_check.py check` |

## Tasks and order

| # | Task | Waits for |
|---|---|---|
| T0 | Gate runner and baseline | SDK T1 |
| T1 | The SDK rows PqChat needs (spec §5), clientkeys rows first | SDK T21, T10, T3 |
| T2 | Crate skeleton, errors, storage interface, dependency rule | SDK T1 |
| T3 | Vectors through the SDK | T1, T2 |
| T4 | Record checks, trusted reads, replicas, instances | T3 |
| T5 | Sessions, epochs, wraps, removal, leave, `msig` expansion | T4 |
| T6 | Messages: chain positions, content, envelope, order | T5 |
| T7 | Stores: chain store, `postMessage`, the store list, spend consent | T6 |
| T8 | The Matrix transport trait, binding and conformance | T6 |
| T9 | Recovery from state, pending until accepted, locked seed, device binding | T7, T8 |
| T10 | Public topics | T4 |
| T10b | Attachments (owner 2026-11-21, O9 (b)): the SDK's file-seal call, `file` content sent and read, ciphertext on Arweave, `ctSha256` checked, size padded | T6, TODO 8i research + its `ua-rs` / `scaas-rpc` parts |
| T11 | **Real-crypto end-to-end run, local** | T1–T10 |
| T12 | Bindings check over the one library | T11, SDK T20 |
| T13 | The same end-to-end run on the SCaaS testnet | T11; the next testnet reset; the owner's word |
| T14 | Docs and summary | T12 |
| T15 | Closing review | T14 |

T5 and T10 may run beside each other; T7 and T8 too. Every other task in order.

**Round 2 order (owner 2026-11-22).** After T11's local run and T12's first bindings check (red by its finding):
1. the round-2 mutants for the contact card and the room check (done: `0f78ce0aa`);
2. T12: decrypted content reaches the bindings only as the SDK's `SecretBytes` handles, plus the glue fixes (the crate's
   `Drop` enum renamed, the SDK `use` lines in the reference library's `api`);
3. T10b: the two new calls (vectors first), PqChat's `app_id`, `open_file`'s `ctSha256` check on every open path, the
   `file` content rows;
4. merge `origin/ua-rs-sign` into `pqchat-core-impl` and run the reconciliation checks;
5. only then the rest of T11 over Matrix and the T11 mutants that need the hostile-envelope and reorg fixtures.

## T0 — Gate runner and baseline

**Files:** `clients/pqchat-core/runs/2026-11-17-pqchat-core-gates.sh`, the summary file.

- [ ] Write the runner with the steps above (per-step log, resume, summary), the SDK plan's runner as the model.
- [ ] Run `--only docs` and `--only ck-test` on the clean tree: green, the baseline in the summary.
- [ ] Commit `pqchat-core T0: gate runner and baseline`.

## T1 — The SDK rows PqChat needs, clientkeys rows first

The spec's §5 rows, in the PqChat-shaped form its §13 O3 recommends unless the owner answers otherwise, added to clientkeys (rows),
`ua-rs` and the SDK, nowhere else. **Files:** `clients/clientkeys/src/pqchat.js`, `clients/clientkeys/scripts/pqchat-vectors.mjs`,
`smartcontracts/vectors/pqchat/` (regenerated), `clients/ua-rs/src/wallet/` (the PqChat entries K2–K6, S1–S6, V1, V2, padding and
canonical JSON), `clients/scaas-sdk/src/` (their SDK entries, behind `pqchat-records`), their tests.

- [ ] List which rows the SDK's App cores section gives as specified and which it lacks; the list goes in the commit message.
      **If a key row needs key bytes above the SDK, or a record row needs the generic app signing call, stop and report** (spec §13
      O1, O3).
- [ ] **clientkeys first** (spec §10): canonical JSON rows with keys ordered differently in UTF-16 and UTF-8, a control character,
      an integer at `2^53 − 1`; `unpad` refusal rows (non-zero fill, a wrong bucket, a length past the end); a chain read at counter
      5,000 from `ck_0`; the stateless path of `decryptMessage` changed from `c > MAX_SKIP` to the walk bound of CLI-PQC-14 (2^20),
      with its test. `npm test` green; vectors regenerated by the generator.
- [ ] Tests first, against `smartcontracts/vectors/pqchat/`: each signing entry reproduces the row's typed digest, id and
      `uaMessage`, and its `UASig` verifies (fixed randomness under the vectors build); S1 / S2 seal `sealedInfo` from named fields
      and compute `wrapHashes` inside, the review listing the store list and Matrix ids as request fields; K2 in the SDK's form
      reproduces every `wraps` row with the SDK building the scheme byte and `kemPkHash`, and refuses every `p14` row by name
      (`KemKeyInvalid`); K3 gives `ck_0` and `advance` gives every `chains` step and the counter-5,000 row in one call; S5 reproduces
      `message`, `envelope`, `payload` and `matrixEvent` from the content value; K4 and K5 open them, the canonical check
      re-serialising and comparing; the new canonical JSON and `unpad` rows; K6 the hint; V2 decodes every blob and payload row and
      refuses a truncated or over-deep one.
- [ ] Refusals, one change at a time, each with its positive control: a label outside `scaas/pqchat/v1/` (`AppLabelRefused`); an
      `advance` on a position of another app scope (`AppHandleForeign`) or past 2^20; the hint call on a chain position (§5.3 item
      3); a generic `mac_derive`, if one remains, with a message under the prefix (item 6); the generic app signing call with
      `PURPOSE_PQCHAT` and with `DS_C`; S5 with an `msig` sender; a handle's usage tag changing no byte of any row (item 4); no
      entry takes a digest or a caller-made ciphertext (doc test); no handle is `Clone`, `Debug` or readable (compile-fail tests).
- [ ] Code; green.
- [ ] Gates: `ck-test`, `ua-test`, `sdk-test`, `pqc-tree`, `docs`.
- Mutants, each killed by its own test: K2 without the P14 modulus check; K2's info without `kemPkHash`; K2's AAD without `keyId`;
  K3 with a salt; `advance` swapping the `0x01` and `0x02` messages; S5 dropping the AAD; S1 hashing `wrapHashes` in the wrong
  order; the canonical check sorting by UTF-8; `unpad` accepting a non-zero fill; V1 accepting a non-minimal `msig`; V2 without the
  depth bound; the hint call accepting a chain position.
- [ ] Commit `pqchat-core T1: SDK, ua-rs and clientkeys rows for PqChat (spec §5)`.

## T2 — Crate skeleton, errors, storage interface, dependency rule

**Files:** `clients/pqchat-core/{Cargo.toml,Cargo.lock,src/lib.rs,src/error.rs,src/store.rs}`, `tests/deps.rs`.

- [ ] `publish = false`, the repository's `rust-version`, SPDX line; dependencies: `scaas-sdk` (features `app-core` and
      `pqchat-records`), `tokio`, `serde`, `serde_json` (content values only, never written as signed bytes), `uuid` (v4), `tracing`,
      `thiserror`; nothing that touches a key, a node or Matrix.
- [ ] Tests first: `pqc-tree` refuses `scaas-ua`, `scaas-rpc`, `matrix-sdk` in the normal graph (a positive control: the check
      fails on a branch that adds one); `PqChatError::code()` names of spec §8, stable; no error's `Display` or `Debug` holds an
      input (a property test over every variant with marked inputs); the storage interface keys items apart, each written at its
      expected revision (`StoreConflict` after three tries), a failed write keeps the old item (`StoreIo`).
- [ ] Code; green. Gates: `pqc-test`, `pqc-clippy`, `pqc-deny`, `pqc-tree`, `pqc-wasm`.
- Mutants: drop the revision check; one revision for all items; let an error carry its input.
- [ ] Commit `pqchat-core T2: crate skeleton, errors, storage interface`.

## T3 — Vectors through the SDK

**Files:** `clients/pqchat-core/tests/vectors.rs`.

- [ ] Tests first: every row of spec §10's middle column, read from the four files, produced through the SDK's vectors build: ids,
      scopes, typed digests, `sigHash`, record blobs, wraps, `wrapHashes`, P14 refusals, message ciphertext and AAD, envelope,
      payload, the Matrix event (its padded base64 exactly), `sealedInfo`, hints; the topic rows. A row that cannot be produced
      through the surface is a T1 gap, reported, never worked around.
- [ ] Every unbound field non-zero in some row (`via`, `device`, `parents`, `ref`): asserted on the rows themselves, so a generator
      change that zeroes one fails here.
- [ ] Code; green. Gates: `pqc-vectors`, `pqc-test`, `ck-test`.
- Mutants: the Matrix event written unpadded; the parents passed unsorted to S5.
- [ ] Commit `pqchat-core T3: vectors through the SDK`.

## T4 — Record checks, trusted reads, replicas, instances

**Files:** `src/check.rs`, `src/instance.rs`, `src/reads.rs`, `tests/check.rs`, `tests/reads.rs`.

- [ ] Tests first (CLI-PQC-07), each negative with its positive control, its own fixture, the reason asserted and the no-reaction
      assertion:
      - `envelope`: a flipped byte of `env`;
      - `decode`: a record over the size or depth bound, a non-canonical base64;
      - `signature`: a record signed by another member's key (hostile harness);
      - `member`: a sender not a member of the epoch at home;
      - `counter`: two **different** records of one sender and device with one counter (distinct `messageId`s), the second dropped;
      - `duplicate`: one record arriving on two stores, the second dropped before the counter check;
      - `replica`: a replica record differing from the home's under the same id;
      - `unlisted`: a record from an instance the factory does not list (`InstanceUnlisted` for the user's own action);
      - `wrap-hash`: a wrap read from state whose `hashStruct` differs from the signed record's `wrapHashes[i]`, refused before any
        decapsulation (a recording fake of K2 sees no call);
      - control-plane rules: an epoch whose number is not the parent's plus one, an author without the rights at the parent,
        unsorted members, a creator absent from `admins`;
      - a `messageAt` record counted only from a listed instance under trusted reads, with membership re-checked at home (K12).
- [ ] Trusted reads (CLI-PQC-13): a fake endpoint list with a discovered endpoint first that substitutes `kemKeyOf`, and one that
      serves a stale `latestEpoch`: each refused (`NoTrustedEndpoint`, or the agreement's refusal), nothing encrypted to the
      substituted key, nothing sent under the stale epoch; a KEM version below the highest kept refused (`KemVersionLowered`).
- [ ] Code; green. Gates: `pqc-test`, `pqc-clippy`, `pqc-reads`.
- Mutants, each killed by its own reason: skip the envelope check (`envelope`, on a fixture whose decode and signature would
  pass); skip V1 (`signature`); skip the membership check (`member`); read membership from the replica (`member`, on a replica
  holding a complete competing child); drop the counter check (`counter`); drop the `messageId` dedupe (`duplicate`); skip the
  replica equality (`replica`); skip the factory listing (`unlisted`); skip the wrap-hash check (`wrap-hash`); mark `kemKeyOf` as
  an ordinary read; drop the highest-version check.
- [ ] Commit `pqchat-core T4: record checks, trusted reads, replicas, instances`.

## T5 — Sessions, epochs, wraps, removal, leave, `msig` expansion

**Files:** `src/session.rs`, `src/epoch.rs`, `tests/session.rs`, `tests/chain_session.rs` (anvil). Deploy: the contract's own forge
script (`script/DeployBase.sol` with `DEPLOY_PQCHAT`) into a test `anvil --enable-tx-gas-limit`, through `scripts/capped`.

- [ ] The run's positive control: a transaction above 2^24 gas refused by the chain.
- [ ] Tests first (spec §4 rows Session, Epoch, Remove / leave, Wraps / KEM, `msig`): a 2-member session created with all wraps in
      one transaction; a 20-member one in chunks sized from the SDK's quote, completion only at the last wrap, and again at a low
      block gas limit (more, smaller chunks; nothing assumed about the limit); the creator in `members` and `admins`, both strictly
      sorted; fresh `K` per epoch; a plain rekey by a member; a membership change refused for a non-admin (`NotAdmin`); `remove` then a
      rekey without the removed member; a member who left or was removed authors no plain rekey; a child that loses the home slot
      is rebuilt from the winner (`EpochTaken`); sends held between a child's first sight and its finality (`EpochNotFinal`); wraps to
      the highest KEM version seen; a member's higher version raises `KemVersionRaised` and starts no rekey by itself; an own wrap of
      the winning epoch that does not open starts nothing (shown only); a UA with `checkedOf.kem` `NONE` skipped and named
      (`KemKeyMissing`); a P14-refused key (`KemKeyInvalid`); an `msig` seat expanded into its accepted KEM-holding leaves, two levels,
      `via` set; a record with an `msig` author refused (`MsigAuthorPlanned`); the stand-in wrap bytes of `script/onchain/PqChat.s.sol`
      refused at open.
- [ ] Code; green. Gates: `pqc-test`, `pqc-chain`, `pqc-clippy`.
- Mutants: `epoch = parent` (no `+ 1`); `K` reused from the parent; the creator absent from `admins`; a removed member kept; the
  highest KEM version replaced by the first seen; `via` not set; a rekey started automatically on a raised version; a send under a
  child before its finality.
- [ ] Commit `pqchat-core T5: sessions, epochs, wraps, removal, leave, msig expansion`.

## T6 — Messages: chain positions, content, envelope, order

**Files:** `src/chain_state.rs`, `src/content.rs`, `src/message.rs`, `src/order.rs`, tests.

- [ ] Tests first: counters from 0 per epoch and device, persisted before the send (a crash between persist and send skips a
      counter, never reuses one); **no skipped key kept** and a verified message read at any counter up to 2^20 past the nearest held
      position, by one `advance` call (CLI-PQC-14): a fresh store, a chain at counter 5,000, only its last 10 messages available, all
      10 shown; a counter past the bound shown as unreadable (`too-far`); a member signing messages under 500 new device ids at
      counter 2,000 leaves the held positions within their bound (least recently used dropped) and the arena untouched by kept keys;
      positions derived lazily after a lock; the content types in scope with P49's bounds and an unknown type shown as unsupported;
      the 1,024-B bucket rule for the chain; the envelope's inner bytes equal the `postMessage` arguments (one `messageId`); display
      order by `parents`, then `ts`, then `messageId`; at most 8 `parents`, sorted; a message for an unknown epoch buffered and shown
      when its epoch arrives; an `edit` or `redact` from another UA ignored; a sender stops using an epoch once the home shows a
      complete child.
- [ ] Code; green. Gates: `pqc-test`, `pqc-clippy`.
- Mutants: counter persisted after the send; a walk before the signature check; the walk bound off by a factor; positions unbounded;
  `parents` unsorted; an edit accepted from any UA; the unknown-epoch buffer unbounded.
- [ ] Commit `pqchat-core T6: messages, chain positions, order`.

## T7 — Stores: chain store, `postMessage`, the store list, spend consent

**Files:** `src/stores.rs`, `src/chain_store.rs`, `tests/chain_store.rs` (anvil, `--enable-tx-gas-limit`).

- [ ] Tests first (CLI-PQC-06): one send reaches every listed store its type may use with the same bytes; `typing` goes to the room
      only and is not sent when no room is listed; `storeMessage` payloads paged by `storedRange` (16 per page, an offset past the end
      empty); a stranger's `storeMessage` under a known hint dropped (`signature` or `member`); an empty `env` paged past; a chain
      store without the session's spend consent refuses the send (`ChainCostUnconfirmed`); `receipt` off by default while a chain store
      is listed; `postMessage` only on the user's choice, above 1,024 B only with the cost confirmation (`ContentTooLarge`
      otherwise); a `messageAt` record counted per K12 (T4's rule) against a real posted message; a store list naming HCS or Waku
      refuses the send before anything is signed (`StoreUnsupported`) and the session still reads its chain store; a list with no
      message store, two Matrix entries or duplicate chain entries refused (`StoreListInvalid`); a rekey by a non-admin member that
      adds a chain store: not written to or read until the user confirms (`StoreUnconfirmed`), `StoresChanged` with `by_admin` false;
      a test-chain store warned about.
      Note (2026-11-22): the HCS store stays outside this round (CLI-PQC-02; `StoreUnsupported` kept), and is now unblocked on
      the SDK side: the SDK plan's T43 builds `hcs_submit` and `hcs_read` (owner 2026-11-22, Hedera needed for HCS).
- [ ] Code; green. Gates: `pqc-test`, `pqc-chain`.
- Mutants: send to the first store only; send `typing` to a chain store; skip the spend consent; use a new store without
  confirmation; accept a list with no message store; sign before the store-list check.
- [ ] Commit `pqchat-core T7: stores and spend consent`.

## T8 — The Matrix transport trait, binding and conformance

**Files:** `src/matrix.rs` (the `MatrixTransport` trait, the event codec, room and id binding), `tests/matrix_fake.rs`,
`tests/matrix_conformance.rs` (run against every implementation).

- [ ] Tests first, over a fake transport (spec §6): attach and detach (`MatrixDetached` when detached; chain stores still read);
      the event content `{v, hint, env}` equal to the `matrixEvent` row, padded base64 exactly, an unpadded or URL-safe form dropped
      (`decode`); an event over 65,536 B, a `v ≠ 1`, a hint not 8 bytes dropped; rooms created without Matrix encryption; events of a
      room no accepted session binds ignored; **binding** (K8): a room the account had joined before named by a session is not used
      (shown with the warning), a room named by two sessions serves the first accepted only, a Matrix id not bound to its UA (no
      contact card, no envelope signed by that UA from that sender) neither invited nor removed (`MatrixIdUnbound`); invites only once
      the session is complete at home; no Matrix power level read as a PqChat right; the room id never in a chain write (a scan of
      every prepared operation's fields); a store list changed by a rekey naming a new room: not joined until confirmed; a transport
      failure reported for that store only, the chain stores of the same send still written.
- [ ] **Conformance** (K9): in a bound room the transport sends no read receipt, read marker, typing notice or presence update, and
      joins only on `pqchat-core`'s call; the test runs against the fake here and the e2e's implementation in T11, and is exported
      for `app-matrix` to run in its repository.
- [ ] Code; green. Gates: `pqc-test`, `pqc-clippy`, `pqc-wasm` (the trait compiles on wasm32).
- Mutants: process events of any room; use a room joined before; invite an unbound id; trust a power level for a removal; send a
  Matrix read receipt in a bound room; carry the room id in a chain write.
- [ ] Commit `pqchat-core T8: the Matrix transport, binding, conformance`.

## T9 — Recovery from state, pending until accepted, locked seed, device binding

**Files:** `src/recovery.rs`, `src/consent.rs`, `src/device.rs`, tests (fake and anvil).

- [ ] Tests first: a fresh store finds every session through the factory index and batched `sessionsOf` on each listed instance,
      repeated entries de-duplicated, with progress events (CLI-PQC-09); a session shown only when its home is listed, reachable, holds
      the equal record and `epochCount > 0` (K25); epochs at home after finality; a pending session's own wrap opened only when the
      user looks at it (`preview`); after an explicit `accept`, the latest messages from `storedRange` and the room's history; a fresh
      device makes a new device id and never reuses a counter; **device binding** (K18): a store copied to a second instance with a
      different anchor makes a new device id there, and a missing anchor too; a pending session makes no store read, no Matrix join,
      no subscription, no receipt and no write (CLI-PQC-08, the recording fakes), its room's invite held unanswered, and declining
      writes nothing; events arriving while the seed is locked kept up to the bound, every `net.scaas.pqchat.v1` event including after
      a locked restart, the rest re-read from the room after unlock, none dropped, none answered (CLI-PQC-10); O6's default if the
      owner has answered, otherwise (a) ask again, and in either case a session the UA left counted as declined (K11); a stale
      `latestEpoch` from a discovered endpoint refused (CLI-PQC-13).
- [ ] Code; green. Gates: `pqc-test`, `pqc-chain`.
- Mutants: read an unlisted instance; skip de-duplication; show a session whose home is not listed; open a pending wrap without
  the user's look; join the room before acceptance; drop an event that arrives while locked; keep the old device id on an anchor
  mismatch; count a `leave` as acceptance.
- [ ] Commit `pqchat-core T9: recovery, consent, locked seed, device binding`.

## T10 — Public topics

**Files:** `src/topics.rs`, tests (fake and anvil).

- [ ] Tests first (topics P33–P46): create with `openReplies` true; post by the owner and a granted writer, refused for a revoked
      one; replies open and closed; edits by the author only; votes `+1`, `-1`, `0` with `seq == stored + 1`; every list paged from
      state; a `ref` shown unverified until resolved on its chain (factory listing, the referenced topic's home, `contentHash`), and
      refused as verified when the referenced entry's topic names another home (Fable P3-4); an `msig` topic owner refused
      (`MsigAuthorPlanned`).
- [ ] Code; green. Gates: `pqc-test`, `pqc-chain`.
- Mutants: skip the factory listing of the `ref`'s instance; skip the home check; accept a `seq` jump.
- [ ] Commit `pqchat-core T10: public topics`.
- **For the next `PqChat` release, after the audit** (owner 2026-11-22, "Để sau audit"): a view returning a version's `nonce`
  (`entryOf`, `versionAt` return none), so that a reader rebuilds the referenced `PqTopicEntry` / `PqTopicEdit` typed digest and
  checks a pinned `contentHash`. Until then no contract change: a pinned `contentHash` stays shown as unchecked (`HashUnchecked`).

## T11 — Real-crypto end-to-end run, local

Owner 2026-11-17: "OK, put the e2e into the pqchat-core plan" (CLI-PQC-12). **Real keys, real wraps, real ciphertexts, no stand-in
wrap**: the stand-in wraps of today's on-chain PqChat runs (`smartcontracts/evm/script/onchain/PqChat.s.sol`, `_wraps`) test the
contract only and are not used here. **Files:** `clients/pqchat-core/tests/e2e.rs` (`#[ignore]`), `tests/e2e/harness.rs`,
`tests/e2e/matrix.rs` (a test-only `MatrixTransport` over matrix-rust-sdk at `app-matrix`'s pinned version, a dev-dependency, which
also passes T8's conformance test), `tests/hostile/` (the hostile harness), `clients/pqchat-core/runs/2026-11-17-pqchat-core-e2e-mutants.py`.

**Setup (harness, each part started and stopped by the test):**

- **Chain:** `anvil --enable-tx-gas-limit` through `scripts/capped`; first the positive control (a transaction above 2^24 gas refused
  by the chain), with the harness's own refusal above 2^24 as the second line. The registry, the factory and a `PqChat` release
  deployed by the contract's own forge script (`DEPLOY_PQCHAT`), then **three listed instances**: H (home), R1 (replica), R2 (the
  instance for the conflicting record), and **one unlisted instance** U, a `PqChat` deployed directly, not through the factory.
  Signers that need no precompile: `fndsa512` and `mldsa65` on the registry's cached expanded key. A run with an `mldsa87` signer,
  which verifies only by precompile, uses a local Nethermind with the precompile instead (Docker, `--memory 4g`, a local data
  directory made by `mktemp -d`, never the testnet stack), as the step `pqc-e2e-nethermind`.
- **Matrix:** one Synapse container (`--memory 1g --cpus 1`, spec §13 O10), three users registered through its shared-secret admin
  API; the test's transport implementation logs each in once.
- **Accounts:** three seeds in the SDK's vault (test seeds made at run time), UAs A (`fndsa512`), B (`mldsa65`, cached), C
  (`fndsa512`), each registered with a KEM key, version 1, by self-relay from anvil's funded accounts. Contact cards bind each UA to its
  Matrix id (CLI-PQC-05).
- **Endpoint list:** the anvil endpoint named, so every trusted read (CLI-PQC-13) is served.
- **Hostile harness:** writes an honest client refuses, on the SDK's vectors build and raw calldata, never through `pqchat-core`.

**Steps (each asserted; every honest write through `pqchat-core` over the SDK; every check's drop reason read from `dropped`):**

- [ ] **1:1 session, Matrix and chain store.** A creates a session S1 with B at H, stores the Matrix room and H's chain store, A's
      spend consent given; the wraps are hybrid KEM wraps to B's and A's registered KEM keys (`kemKeyOf`, trusted reads); B finds it
      by `sessionsOf`, sees it pending, its room invite held, accepts (spend consent given), joins the room.
- [ ] **Send and decrypt.** A sends a `text`; B's client receives it from the room and from the chain store, shows it once
      (`duplicate` counted once), and the decrypted content equals A's content byte for byte; B replies; A decrypts; no Matrix
      receipt or typing event appears in the room (read from Synapse's admin API).
- [ ] **1:1 session, Matrix only.** A creates S2 with B, the Matrix room as its only store: send and decrypt as above (used again
      below for the fresh device, K13).
- [ ] **Rekey with removal.** A creates a group session S3 with B and C (A admin). C reads a first message. A removes C (`remove`) and
      rekeys without C; A sends under the new epoch; C's client finds no wrap of its own, holds no `K` for the new epoch, and does not
      decrypt the new message from either store (asserted on C's client: nothing shown, nothing sent). Through the hostile harness:
      C's plain rekey of the old epoch is refused by the contract (`PqChatNotMember`) and C's `postMessage` under the old epoch is
      refused (`PqChatEpochTaken`).
- [ ] **Fresh device.** A new store and a new device anchor for B (same seed): `sessions` finds S1, S2 and S3 from state alone
      (factory index, `sessionsOf`, `epochsOf`), all pending (B authored no record at home); nothing is read from a store before
      `accept` (recording transport); after an explicit `accept` of each, B opens its wraps, reads the latest messages of S1 from
      `storedRange` and of S2 from the room's history (no Matrix encryption in the room, so the seed alone suffices), decrypts them
      equal to what was sent; B sends from the new device with a new device id; A decrypts it.
- [ ] **Long chain.** A sends 5,000 `text` messages in S2 (a scripted loop through `pqchat-core`); a second fresh store
      for B, whose test transport serves only the room's last 10 events, shows all 10 (CLI-PQC-14).
- [ ] **Replica.** S1's records copied to R1: B's client reads the epoch there and accepts it only as equal to the home's. A's second,
      different session record with S1's nonce is landed in R2 by the hostile harness (in R1 it would be `PqChatNonceUsed`): B's client
      does not count it (`replica`) and reads membership from H. C, through the hostile harness, lands in R1 its own complete child of an
      S3 epoch that A's child holds at H: B's client follows H.
- [ ] **Public topic.** A creates a topic at H; A posts; B replies and votes; the pages from state show them; an entry of R1 referenced
      with its `contentHash` resolves as verified; one referenced in U is shown unverified (`unlisted`).
- [ ] **Mutants, one per decryption or verification check, each with its own fixture and killed by its own reason**, applied alone
      through the mutants script; record `…-e2e-mutants.txt` (all killed):

      | # | Mutant | Fixture | Killed by |
      |---|---|---|---|
      | 1 | K2 unwrap binding another KEM version's key hash | B re-registers a KEM key at version 2 before S1; A wraps to version 2 | B cannot open S1's wrap: every S1 assertion red |
      | 2 | the envelope check skipped | an `env` that is a valid record and signature sealed under another epoch's `k_env` (hostile) | reason `envelope` absent, message shown |
      | 3 | V1 skipped | a record with B's sender field signed by C, sealed under `k_env` (hostile; C holds S3's old `K`) | reason `signature` absent |
      | 4 | membership read from the replica | C's competing child in R1 (Replica step) | C's message under that child shown (reason `member` absent) |
      | 5 | the home slot ignored | the same competing child | B follows R1's child |
      | 6 | the counter check dropped | two different records of A, one device, one counter (hostile) | reason `counter` absent |
      | 7 | the `messageId` dedupe dropped | one record on the room and the chain store | shown twice, reason `duplicate` absent |
      | 8 | the replica equality skipped | the conflicting record in R2 | reason `replica` absent |
      | 9 | the factory listing skipped | a session for B in U (hostile) | the session shown, reason `unlisted` absent |
      | 10 | the wrap-hash check skipped | a named recording endpoint that serves a wrap differing from the one in state (the contract refuses such a wrap, so the endpoint is the fixture) | a K2 call recorded, reason `wrap-hash` absent |
      | 11 | the `sealedInfo` open's check skipped | a recording endpoint serving a changed `sealedInfo` | a store joined from it |
      | 12 | `unpad` accepting a non-zero fill | a message whose plaintext has a non-zero fill (hostile, sealed under `mk` by the vectors build) | reason `content` absent |
      | 13 | finality ignored | a child read at a non-final block, then reorganised away on anvil (`anvil_revert` to a snapshot) | a send under the vanished child |
      | 14 | the pending gate removed | a new pending session from C | a Matrix join before `accept` |
      | 15 | a discovered endpoint allowed for `kemKeyOf` | a second, discovered endpoint first in the list, substituting B's key | A wraps to the substituted key |

- [ ] Gates: `pqc-e2e`, then `pqc-e2e-nethermind` if an `mldsa87` signer is in the run; per-step logs; the summary row with the
      transaction hashes of the run's writes.
- [ ] Commit `pqchat-core T11: real-crypto e2e, local (CLI-PQC-12)`.

## T12 — Bindings check over the one library

**Files:** the SDK's reference library `clients/scaas-sdk/ffi` with `pqchat-core` linked behind a test feature, or a sibling
reference crate if the SDK plan keeps that library SDK-only.

- [ ] Tests first: the SDK's generators (FRB 2; UniFFI with the C++ generator, or the fallback the SDK's spike chose) run over the
      library and generate `pqchat-core`'s public API with the SDK's surface rules; no handle type and no byte accessor of one in the
      generated surface (a grep of the generated sources); `attach_matrix` and the storage interface absent from it; decrypted
      content only through the SDK's copy calls; the library's symbols and enabled features hold no vectors-build entry (K30).
- [x] Code; green. Gates: `bind`, `pqc-test`. (Round 2, owner 2026-11-22 "Handle SecretBytes": decrypted content and
      `sealedInfo` plaintext only as the SDK's `SecretBytes` handles, held member by member by `runs/bind_surface.py`;
      the decisions entry of 2026-11-23.)
- [x] Commit `pqchat-core T12: bindings check`.

## T13 — The same end-to-end run on the SCaaS testnet

**On the owner's word only, at the testnet's next reset** (the reset deploys the `PqChat` release; this task deploys no release).
The T11 steps against `scaas-testnet` (7622) with its factory's listed instances, a local Synapse as in T11, the signers the
testnet's precompiles serve; builds through `scripts/capped`, the broadcasts outside `capped` under a ~1 GB cap; progress lines with
addresses, UAs and transaction hashes, never keys. No mutant and no hostile write on the testnet (T11 holds them). The replica
instances the run creates are contracts: each is verified on the testnet's explorer, with the completeness check, before the task
closes. The run also answers whether the chain refuses what anvil let through (K16).

- [ ] Commit `pqchat-core T13: e2e on scaas-testnet` with the summary row.

## T14 — Docs and summary

**Files:** `docs/clients/pqchat-core.md` (status per section: BUILT only where code and tests exist), `docs/contracts/pqchat.md`
§14, the UA-7 plan's client rows pointed here, `docs/decisions.md` (Changes on CLI-PQC entries for what moved), the summary.

- [ ] `docs` gate green; the summary complete (`step | commit | rc | counts`).
- [ ] Commit `pqchat-core T14: docs and summary`.

## T15 — Closing review

- [ ] **Fable, full review** (design, security, cryptography) of the spec, the crate, T1's SDK, `ua-rs` and clientkeys rows and the
      e2e, against UA-7, the contract and CLI-PQC-01 to CLI-PQC-14; every finding fixed or answered in the spec's review section, each
      fix with its test.
- [ ] **Codex, only on the owner's word**, one review type at a time, with the model and effort from its own configuration.
- [ ] Report: what is built, the summary, the open points still unanswered (spec §13). Merge and push on the owner's word only.
