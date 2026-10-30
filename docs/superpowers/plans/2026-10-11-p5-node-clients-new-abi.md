# P5 — Node, clientkeys and encoders on the new ABI; the v1 line to `legacy/p5/` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** MT-8, MT-9 and every TODO/HANDOFF item tagged P5 (TODO.md §00 phase row P5, **P5 — MT-8, MT-9**, the "v1
line to backup" items under P3 and P5, MT-1/MT-3's v1 part, P1b note (c), P2b-1's `SCaaSDexV1` move, P3's "client ABI
(P5)", HANDOFF P4 "the node's call table for the renamed rows (P5)"): `scaas-node` leaves the v1 line (`MetaToken`'s
salt-less `executeMetaTransaction`, `SCaaSDexV1`, the v1 KATs `metatx_v1_kat.json` / `dex_kat.json`, the deploy keys
`factory`/`implementation`/`dex`/`scaas_dex`) for the built tree: `MetaTransaction` and `MetaTransfer` in the salted
domain (`salt = chain_uid`), the jobs naming their struct, the mesh EVM body, the Hedera KAT; the DEX venue on the
`SCaaSDex` clone (`TradeOrder` / `DexOrder`, `mtxSettle` settlements of one taker and its makers, outside legs through
the `DexPuller`, cancels where the order lives, `SigCheckGasStarved` and the empty `MatchFailed`); a money-safety guard
before every simulation and signature (call table PAY-FIX2 / NODE-JOB-19 with the P4 rows, selector tables from
`mtxSelectors()` NODE-JOB-20, `chainUid()` binding NODE-GW-07, `mtxSettle` gas sized by simulation, the ERC-1271 gas
floor 400 k·64/63 + 5 k of P1b note (c), `MinNonceNotIncreasing` = done); clientkeys' payment check off v1 (L15) onto
`MetaTransfer` with `chainUid`, trade-order and cancel typed data, the self-call check by allowlist; the forge KATs carry
the relayed calldata so both sides are byte-identical; the v1 contracts, tests, vectors and deploy path to
`smartcontracts/evm/legacy/p5/`, the node's and clientkeys' v1 encoders to their own `legacy/p5/` (owner: backup, not
delete); the docs, TODO and HANDOFF. bamboo-dms is out of scope: its follow-up is listed in [bamboo-dms handoff](#bamboo-dms-handoff-out-of-scope).

**Architecture:** Three layers, each pinned by the forge KATs. (1) **Encoders**: `scaas-node/src/abi.rs` copies the
structs, interfaces, events and errors from `smartcontracts/evm/src` (never inferred); `src/metatx.rs` holds the wire
forms (`WireMetaTx`, `WireMetaTransfer`, `deny_unknown_fields`), the salted `Domain`, `enum Mtx { Call, Transfer }` with
digest, struct hash and relayed calldata; `src/dex.rs` the `TradeOrder` wire form, the settlement mirror (min fill,
maker ceiling, fees by role) and the book; clientkeys `src/evm.js` the same typed data by a nested EIP-712 encoder. Every
digest and every calldata is compared with `metatx_kat.json`, `metatransfer_kat.json`, `trade_kat.json`,
`dex_order_kat.json`, `hedera_kat.json` (the forge tests write them and execute the calldata they write). (2) **Money
safety**: a new `src/guard.rs` with pure rules (call table, `Facts`/`allowed`, `self_call_ok`, `gas_limit`,
`settled_all`, `next_gas`, `already_invalidated`) and a cached `Guard` (`chainUid()` bound set, allowlists) that the
submitter runs before `simulate` and signing; `Chain::uid()` reads block 0 or the configured `chain_uid` and a lane
refuses to start on a mismatch. (3) **Venue**: `src/dex/venue.rs` reads token kinds and the puller from the DEX, plans
one `Settlement` per taker, simulates the whole `mtxSettle` and attributes a failure from the order hashes in the
revert data (`settleOne` per settlement), sends SCaaS cancels as `metatx` entry jobs on the sell token and outside
cancels as one DEX `mtxCancelOrders` call, and watches `LegSettled`/`MatchFailed`/`OrderCancelled`/`NoncesInvalidated`
on the DEX and the market tokens. The v1 line leaves the build last (Task 6), after nothing reads it.

**Tech Stack:** Rust (alloy 1.6 `sol!`, axum fakes; `scaas-node` e2e on anvil), Solidity 0.8.37 (`osaka`), Foundry
(forge 1.3.5), OpenZeppelin 5.2.0, forge-std 1.16.2; `clients/clientkeys` (`node --test`, `@noble`); Python 3
(`cryptography`, the Hedera ED25519 KAT generator); `scripts/docs_check.py`.

**Spec:** `docs/node/job-api.md` (NODE-JOB-01, -19, -20, §11 call table, the `metatx` struct), `docs/node/gateway.md`
(NODE-GW-07), `docs/node/submit-lanes.md` (NODE-LANE-09, -10, -11, -25), `docs/node/dex-venue.md` (NODE-DEX-02, -08,
-12, -15, -16, -17, -18), `docs/node/mesh.md` (the EVM body, UNKNOWN_CHAIN), `docs/node/store.md`,
`docs/contracts/metatx.md` (CTR-MTX-15, -19, -21, -23, -25, §15 KATs, §16 transitional), `docs/contracts/dex.md`
(CTR-DEX-08, -13, -15, -16, -18, -24, §13 transitional), `docs/contracts/token-wrappers.md` (CTR-TOK-24, -25),
`docs/contracts/accounts.md` / `mandates.md` (P4 rows of the call table, `StaleEpoch`), `docs/clients/signers-clientkeys.md`
(CLI-SGN-05, -08, -27, -33…36), `docs/networks/evm.md` (NET-EVM-05 deploy JSON), `docs/networks/hedera.md` (NET-HED-*);
TODO.md §00 P5 row, **P5 — MT-8, MT-9**, P1b note (c), MT-1, MT-3, the P2b-1/P3 notes; HANDOFF.md P4 "Not done / next".

**Base:** `main` at `e468d8c` (P4 merged `ebacaac`; 1001 forge tests; P3b in flight on `p3b-zether`). Every code block
below was applied task by task to a scratch worktree from `main` (`e468d8c`) and run green: forge 1002 after Task 1 (1001 + `DexKatTest`) and **844** after
Task 6 (158 v1 tests moved to `legacy/p5/`), size gate 0 errors after Tasks 1 and 6 (no other task touches `src/`),
`FOUNDRY_PROFILE=private7622 forge build` green; `scaas-node` `cargo test --lib` 242 / 246 / 254 after Tasks 2 / 3 / 4
(254 after Task 6), `mesh_vectors` 4 + `fuzz` 1, clippy clean, e2e **4/4** and e2e_hedera **1/1** after each of Tasks
2, 3, 4 and 6; clientkeys 60 (58 pass, 2 skipped; P4 had 56/54/2); docs checkers 0 errors and 0 fact misses;
mutation probe **39/39** killed.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; worktree `.claude/worktrees/p5` on branch `p5-node-abi` from `main`.
  forge in `smartcontracts/evm` of the worktree: `lib/` is not tracked — `mkdir lib`, copy
  `smartcontracts/evm/lib/forge-std` into it, symlink `lib/openzeppelin-contracts → /home/ha/work/blockchain/openzeppelin-contracts`.
  clientkeys: symlink `node_modules` from the main checkout (never `git add` it). Heavy commands (cargo, forge, anvil,
  npm) only through `scripts/capped`, one at a time. `/usr/bin/grep`; in worktrees a hook blocks bare `git`: use
  `/usr/bin/git`. Rust: `CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/scaas-node/target` for the node.
- Gates: `forge build` then `forge test` in `smartcontracts/evm`; size gate `forge build src --sizes --json >
  /tmp/sizes.json; python3 scripts/size_gate.py /tmp/sizes.json smartcontracts/evm/size-baseline.json`; in `scaas-node`
  `cargo test --lib`, `cargo test --test mesh_vectors --test fuzz`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --test e2e -- --ignored --test-threads=1` and `cargo test --test e2e_hedera -- --ignored` (a full
  `forge build` first so the e2e's `forge script` does not compile under its timeout); `npm test` in
  `clients/clientkeys`; `python3 scripts/docs_check.py check` and `python3 scripts/docs_check.py facts check`.
- Owner rules: superseded code goes to `legacy/p5/` by `git mv` (backup, never delete) — `smartcontracts/evm/legacy/p5/`,
  `scaas-node/legacy/p5/`, `clients/clientkeys/legacy/p5/`; every chain is a test chain (no migration: redeploy, users
  re-sign resting orders); code size is not a concern (ratchet baseline); open questions stay open unless blocking;
  rulings are N1–N18 here, component docs say "controller ruling, pending the owner", never an N-id; `SmartKeyAccount`
  names contract accounts only.
- Tests: compute anything that makes an external call (`mtxDigest`, `mtxTransferDigest`, `payLane`) **before**
  `vm.prank` / `vm.expectRevert`. KAT writers run under `WRITE_KAT=true` only and every KAT test executes the calldata it
  writes. Every mutant of the probe (Task 4) is killed by `cargo test --lib`.
- Pages over their line budget (`docs_check.py` notes/warns) change by net ≤ 0 lines; `docs/history/` and
  `docs/decisions.md` are records (only `dropped-artifacts.tsv` gains rows).
- Commit trailer (both lines): `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01GBLbPyQuG5HXALewwBZ7Bb`. Never `git add claude-code-api.txt`.

## Review Focus

- **Byte-identical encoders (metatx.md §15).** Node and clientkeys reproduce every digest **and** every relayed
  calldata the forge tests write and execute: `call_digest_and_calldata_match_forge_kat`,
  `transfer_digest_and_calldata_match_forge_kat` (metatx.rs), `kat_hashes_and_calldata_match_forge` (dex.rs:
  `TradeOrder`, `DexOrder`, `mtxSettle`, cancels), `entry_jobs_encode_as_the_token_reads_them` (submit.rs:
  `mtxCancelOrder`, `mtxInvalidateNonces`, `mtxWrap`), `the_call_table_is_pinned` (guard.rs), the Hedera KAT test
  (adapters/hedera.rs); clientkeys `MetaTransfer payment = forge KAT …`, `TradeOrder, CancelOrder, InvalidateNonces in the token domain = forge KAT …`,
  `DexOrder (nested TradeOrder) and the DEX cancels in the DEX domain = forge KAT …` (`test/evm.test.js`). The forge side:
  `TokenKat.t`, `TradeKat.t`, `test/v2/DexKat.t`, `test/hedera/HederaKat.t` (each executes what it writes).
- **The wire never guesses (N1).** `deny_unknown_fields` on both wire structs; `struct` absent = `transfer`; a `call`
  body with transfer fields (or the reverse) is refused; `normalize` zeroes an unbound `relayer`/`feeRecipient` and the
  digest is unchanged (`wire_rejects_garbage_and_the_other_struct`, `normalize_zeroes_unbound_fields_and_keeps_the_digest`).
- **A lane spends nothing it was not asked to (PAY-FIX2, NODE-JOB-19).** A `call` job: selector in the call table, target
  bound to this chain, never a registered token or the token factory; `deploy` only on the account factory, DEX rows only
  on the chain's DEX (`each_rule_needs_its_target`, `an_entry_job_is_only_an_entry`,
  `the_guard_runs_before_simulation_and_signing`; e2e: a `call` job `transfer` on a token → `CALL_TARGET_REFUSED`).
- **Self-calls by the contract's own allowlist (NODE-JOB-20).** `mtxSelectors()` and `supportedModes()` read from the
  target, cached: unlisted selector, `PERCENT` on an `ABSOLUTE` selector, a short `AMOUNT` basis, an unknown fee class or
  an unsupported mode bit ⇒ `SELECTOR_NOT_ALLOWED` before simulation (`self_calls_follow_the_published_allowlist`; e2e: a
  `call`-struct `transfer` → `SELECTOR_NOT_ALLOWED`, then `cancelNonce(99)` mined and lane 99 at 1).
- **Chain binding (NODE-GW-07).** `Chain::uid()` = block 0 hash or the configured `chain_uid`; a wrong pin refuses the
  lane's start (`chain_uid_is_block_zero_and_a_wrong_pin_is_refused`); every meta-tx and entry target must answer the
  same `chainUid()` (e2e: a metatx to a foreign contract → `CHAIN_UID_MISMATCH`, nonce unchanged).
- **Gas (P1b note c, P2b-2, CTR-DEX-08).** A contract signer gets ≥ 432,349; `mtxSettle` is sized ×1.5 until every
  `ok[i]` is true and never past `max_gas_per_tx`; a whole-call revert is final (`gas_floor_and_settle_sizing`); the venue
  splits a `SigCheckGasStarved` multi-settlement and simulates each alone; an empty `MatchFailed` reason is `out_of_gas`.
- **The settlement mirror (CTR-DEX-15/16).** 50 % effective minimum fill, maker receive = `ceil(x·R/A)` and nothing
  else, fee per role at intake, self-trade and dust makers skipped, a crossing remainder dropped, IOC never rests or is
  restored, makers restored first (`the_minimum_fill_binds_makers_and_takers`, `limits_and_the_settlement_mirror_the_contract_including_rounding`,
  `fee_rates_by_role_at_intake`, `restoring_both_sides_rematches_instead_of_leaving_a_crossed_book`, `admit_enforces_the_intake_rules`).
- **Done is done (MT-8).** `MinNonceNotIncreasing` on an `mtxInvalidateNonces` (token or DEX) is consumed
  `already_invalidated`, never dead (`an_invalidation_already_done_is_success`); a cancel-all already in force sends no job.
- **No orphaned consumer of v1.** After Task 6 nothing outside `legacy/` names `MetaToken`, `HederaMetaToken`,
  `OpenFactoryV1`, `MetaTxDex`, `SCaaSDexV1`, `executeMetaTransaction`, `metatx_v1_kat.json`, `dex_kat.json`; the e2e
  deploy asserts the v1 keys `factory`, `implementation`, `dex`, `scaas_dex` are absent; `MetaTxGasV2.t` keeps the v1
  numbers as frozen constants.

## Rulings (docs vs code) and defaults taken

- **N1 — Naming the struct.** A `metatx` job and a gateway body carry `struct: "call" | "transfer"`; absent =
  `transfer` (every pre-P5 job was a token transfer or payment); the wire structs are exactly the Solidity fields
  (camelCase), unknown fields refused. `ua_metatx` stays deferred (UA F1).
- **N2 — Where `chain_uid` comes from.** Block 0's hash from the RPC, or `chain_uid` in the chain config (Hedera and any
  RPC without block 0); both present and different ⇒ the lane refuses to start. A contract's `chainUid()` answer is
  cached only when it matches (a not-yet-bound contract is asked again).
- **N3 — The call table as built.** Rows only for contracts that exist on the tree: `SmartKeyAccountFactory.deploy`,
  `mtxExecuteAsOwner` (one selector on `SmartKeyAccount` and `MandateWallet`, so the wallet's rule: self-authenticating),
  `mtxExecuteAsOwnerRaw`, `mtxPayUnderMandate`, `mtxRevoke`, and the DEX rows `mtxSettle`, `mtxExchange`,
  `mtxExchangeVia`, `mtxCancelOrders`, `mtxInvalidateNonces`. Token entries (`mtxCancelOrder`, `mtxInvalidateNonces`,
  `mtxWrap`) are `metatx` jobs naming their `entry`, never `call` rows; no `transfer`/`approve`/`transferFrom` row.
- **N4 — Selector-table intake.** The node checks what `MetaTxBase._checkCall` checks from the published table (selector,
  fee class, `AMOUNT` basis argument, `PERCENT` on `ABSOLUTE`, mode bits); the static ABI length stays the contract's
  check and the node does not re-encode `data` canonically. Zether self-calls are relayed opaquely with the selectors the
  chain publishes, so the P3b renames need no node change.
- **N5 — Gas.** `mtxSettle`: estimate +20 %, ×1.5 until every settlement settles, capped at `max_gas_per_tx`; a whole-call
  revert is the answer (never retried with more gas: `SigCheckGasStarved` is forgeable by a hook-token destination). A
  meta-tx whose `from` has code gets ≥ `21 000 + 400 000·64/63 + 5 000 = 432,349`.
- **N6 — An invalidation in force is success.** `MinNonceNotIncreasing` from a token's or the DEX's
  `mtxInvalidateNonces` ⇒ consumed `already_invalidated`; the gateway's cancel-all reads `minNonce` first and sends no
  job when it already holds.
- **N7 — Venue rules.** One settlement per taker (its makers in price-time order); a maker below its own minimum is
  skipped for a deeper one; the taker settles iff it takes ≥ its minimum or closes; a remainder that would cross is
  dropped (cancelled in the book), never rested crossed; `ESCROW` refused at intake; fee rate by role (a resting order
  needs the maker rate, and the taker rate only if it would cross); one trade row per settlement listing its makers;
  cancels go where the order lives (SCaaS sell token ⇒ `mtxCancelOrder` entry job on it; outside ⇒ DEX
  `mtxCancelOrders`); bodies name `sellToken`; restore puts makers back before takers.
- **N8 — Attribution.** From the order hashes in the revert data of `settleOne(s, relayer)` (`from = DEX`); without one,
  each maker's chain state (`pulled`, `minNonce`, balance, allowance to the puller) decides; never guessed.
- **N9 — Out of gas.** A `SigCheckGasStarved` multi-settlement simulation is split and each settlement simulated alone;
  an empty `MatchFailed` reason is reported `out_of_gas` and blames no order.
- **N10 — Mesh EVM body.** `{domain, struct, meta_tx, signature, sig_kind}` with `salt` from the chain's `chain_uid`
  (none ⇒ `UNKNOWN_CHAIN`); a `call` self-call's effective `PERCENT` fee is 0 for the policy check; selector names
  `transfer` / `pay`. The mesh vectors are regenerated.
- **N11 — Hedera KAT v3.** `hedera_kat.json` is a `NormalToken` clone on chain 296 (`payLane`) signed by ED25519
  over the v3 digest (`gen_hedera_kat.py`, seed `sha256("scaas.hedera.kat.v1")`); the v1 KAT and its generator move to
  `legacy/p5/`.
- **N12 — KATs carry calldata.** `metatx_kat.json`, `metatransfer_kat.json`, `trade_kat.json` gain the relayed
  calldata (digests unchanged); `dex_order_kat.json` is new (DEX domain, `DexOrder`, `mtxSettle`, DEX cancels).
- **N13 — Deploy.** Two kind-`NORMAL` `PAYABLE` demo tokens from `OpenFactory.createToken` (`demo_token` bUSD,
  `demo_token_2` bPTS; half of each to `DEMO_HOLDER`); the DEX via `createDex` in the e2e; v1 keys gone. The e2e never
  encodes `TokenConfig` (P3b appends to `ConfidentialConfig`).
- **N14 — The v1 line to `legacy/p5/`.** `git mv` of the v1 sources, tests, vectors, Hedera smoke; files that mixed v1
  and v2 are cut (the v1 part to `legacy/p5/`, e.g. `FeePolicyV1.t.sol`, `SmartKeyAccountV1.t.sol`,
  `MockZetherImpl.sol`) and `MetaTxLib.LegacyMetaTransaction` leaves the library (backup copy in `legacy/p5/`);
  `MetaTxGasV2.t` compares v2 with the v1 numbers frozen from `main` `e468d8c`. The node's v1 `abi.rs`, `metatx.rs`,
  `dex.rs`, `dex/venue.rs`, `e2e.rs` and clientkeys' v1 `evm.js` are copied to their `legacy/p5/` (not built).
- **N15 — clientkeys.** `checkPayment` checks a `MetaTransfer` (token, `chainUid`, `entryRef`, amount, payee, fee,
  validity; `expectedToken`, CLI-SGN-08); `checkCall` checks a self-call against the contract's allowlist;
  `tradeOrderTypedData` (token or DEX domain), `orderCancelTypedData` (`CancelOrder` or `InvalidateNonces`),
  `checkTradeOrder` refuses an unlisted `dex`, a non-wrapper `receiveToken` for a wrap, an EOA `approve`.
- **N16 — Deferred, stated in the docs.** TradeEngine and `/v1/dex/exchanges` (P7); batching `mtxBatch`/`mtxBatchTransfer`
  and the per-selector breaker (NODE-LANE-11, NODE-LANE-25); NODE-IDX-06 `repeat_of`; `ua_metatx`; client Zether
  encoders (after P3b); non-EVM families (NM-*); the per-poll market re-check (NODE-DEX-08).
- **N17 — bamboo-dms follows.** The other repo's changes are listed in [bamboo-dms handoff](#bamboo-dms-handoff-out-of-scope)
  and in TODO under P5; nothing here edits it.
- **N18 — Docs.** BUILT/SPECIFIED statuses move with the code; the v1 restatements in `contracts/metatx.md` and
  `contracts/dex.md` shrink to one paragraph each; removed load-bearing tokens get `dropped-artifacts.tsv` rows.

## Open questions (not blocking)

- **Q1** Per-poll market re-check (NODE-DEX-08): the venue checks `marketListed` at intake and in simulation only; a
  delisted market's resting orders fail at the next settlement. A poll-time sweep is left open.
- **Q2** dex.md CTR-DEX-08 says the node does not restore an ERC-1271 order whose settlement failed out of gas. The venue
  restores every failed leg still open and funded on chain (the `dex_sync` failed-trade feed carries no reason) and the
  re-match simulation leaves it out if it fails again. Applying the rule needs the reason in `dex_sync` (bamboo-dms).
- **Q3** `already_invalidated` is reported as `consumed`; bamboo-dms may want a distinct state for the UI.
- **Q4** The cancel rate limit (20 per maker per hour) counts `mtxCancelOrder` entry jobs and DEX `mtxCancelOrders`
  items alike; per-token accounting is open.
- **Q5** `mtxExchange`/`mtxExchangeVia` rows exist in the call table but no client builds them (TradeEngine, P7).

## bamboo-dms handoff (out of scope)

Owner merges in the other repo, before the P5 node reaches a chain Odoo uses:

1. Jobs carry `struct` (`call` | `transfer`) and the v3 `metatx` body; `lib/eip712.py` builds the salted
   `MetaTransaction`/`MetaTransfer` digests (`salt = chain_uid`) and tests against `metatx_kat.json`,
   `metatransfer_kat.json` (both gained `calldata`).
2. KAT repoints: `metatx_v1_kat.json` → `smartcontracts/evm/legacy/p5/test/vectors/` (or drop the v1 test),
   `hedera_kat.json` is v3, `dex_kat.json` → `legacy/p5/`, new `dex_order_kat.json`.
3. DEX book API: rows carry `sell_token`; a trade lists its makers `{hash, fill}` with the taker's `taker_hash`,
   `taker_fill`; a failed trade is `{tag, taker: {row, fill}, makers: [...]}`; DEX cancels and invalidations arrive as
   relay jobs (`mtxCancelOrder` / `mtxInvalidateNonces` entry `metatx` jobs, DEX `mtxCancelOrders` `call` jobs) and are
   stored as relay jobs; events `LegSettled`, `MatchFailed` (`out_of_gas` when empty), `OrderCancelled`,
   `NoncesInvalidated` (from the DEX and the market tokens, with `batch`); `dex_markets` lose `fee_on`/`fee_recipient`.
4. A consumed `already_invalidated` report is success.
5. The mesh vectors (`mesh-envelope-v1.2.json`) are regenerated.
6. Deploy JSON keys: `demo_token`, `demo_token_2`; `factory`, `implementation`, `dex`, `scaas_dex` gone.
7. The portal's clientkeys bundle is rebuilt (`checkPayment` with `chainUid`/`entryRef`, `tradeOrderTypedData`,
   `orderCancelTypedData`).
8. The P4 items under TODO "P4" remain (owner call with `chainUid`, mandate epoch).

## Interaction with P3b (in flight on `p3b-zether`)

- **No code overlap.** The node relays Zether self-calls opaquely with the selectors the chain publishes
  (`mtxSelectors()`, N4), so the entry renames (`zetherTransfer`, `zetherTransferCompact`, `zetherTransferNoBundle`)
  need no node change; client Zether encoders wait for P3b (N16). P5 never encodes `TokenConfig`: the e2e takes both
  demo tokens from the deploy, and `DeployBase._demoToken` leaves `conf` zero, which P3b's `MetaTokenBase` requires of
  a non-Zether kind (`ConfigFieldForOtherKind(4)` on a non-zero `disclosureMode`/`auditorMode`). P5 changes no token
  source (`MetaTxLib` loses only the `LegacyMetaTransaction` struct), so `size-baseline.json` is untouched.
- **Text conflicts** (whichever merges second rebases): `TODO.md`, `HANDOFF.md`, `docs/contracts/token-wrappers.md`
  (six P5 hunks, each a v1 sentence now pointing at `legacy/p5/`), `docs/history/dropped-artifacts.tsv` (both append rows: keep both).


### Task 1: The forge KATs carry the relayed calldata; `dex_order_kat.json`

The node and clientkeys must match the contracts byte for byte on what they **send**, not only on what they sign. The
token KATs add the `mtxExecute` / `mtxExecuteTransfer` calldata and execute it by a low-level call; the trade KAT adds
the relayed `mtxCancelOrder` / `mtxInvalidateNonces` calldata and executes both; a new DEX KAT pins the DEX domain, a
`DexOrder` (outside sell token), a maker/taker `mtxSettle` calldata and the DEX cancels, and settles and cancels for
real. Digests already in the vectors do not change.

**Files:** modify `smartcontracts/evm/test/metatx/TokenKat.t.sol`, `smartcontracts/evm/test/metatx/TradeKat.t.sol`;
create `smartcontracts/evm/test/v2/DexKat.t.sol`; regenerate `test/vectors/metatx_kat.json`,
`metatransfer_kat.json`, `trade_kat.json`, create `test/vectors/dex_order_kat.json`.

- [ ] **Step 1: Apply the diff below** (the vector hunks are what `WRITE_KAT=true` writes; check them with Step 2).
- [ ] **Step 2: Regenerate and check the vectors.**
  `cd smartcontracts/evm && WRITE_KAT=true ../../scripts/capped forge test --match-contract 'TokenKatTest|TradeKatTest|DexKatTest'`
  then `/usr/bin/git diff --stat test/vectors` shows only the added `calldata` keys and the new file; then without
  `WRITE_KAT`: `../../scripts/capped forge test --match-contract 'TokenKatTest|TradeKatTest|DexKatTest'` — all pass
  (each test compares its JSON and executes the calldata).
- [ ] **Step 3: Full suite.** `../../scripts/capped forge test` — 1002 passed (1001 + `DexKatTest`); size gate 0 errors.
- [ ] **Step 4: Commit** `P5 T1: KATs carry the relayed calldata; dex_order_kat.json (DexOrder, mtxSettle, DEX cancels)`.

``````diff
diff --git a/smartcontracts/evm/test/metatx/TokenKat.t.sol b/smartcontracts/evm/test/metatx/TokenKat.t.sol
index 00b8511..ad89b9a 100644
--- a/smartcontracts/evm/test/metatx/TokenKat.t.sol
+++ b/smartcontracts/evm/test/metatx/TokenKat.t.sol
@@ -5,13 +5,15 @@ import {Test} from "forge-std/Test.sol";
 import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
 import {NormalToken} from "../../src/metatx/NormalToken.sol";
 import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
+import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
 import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
 import {normalInit} from "../v2/helpers/V2Fixture.sol";
 
 /// KATs of the two structs on a real token (metatx.md "One rule, four places"): `metatx_kat.json` (v3
 /// `MetaTransaction`, `cancelNonce(42)`) and `metatransfer_kat.json` (`MetaTransfer`, a payment on its pay lane
 /// with a bound FIXED fee), both in the token domain "SCaaS MetaToken" of a `NormalToken` clone on chain
-/// 7622 with its real `chain_uid`. `WRITE_KAT=true forge test --match-contract TokenKatTest` rewrites them.
+/// 7622 with its real `chain_uid`, each with the relayed `calldata` (`mtxExecute` / `mtxExecuteTransfer`) that scaas-node
+/// and clientkeys must encode byte for byte. `WRITE_KAT=true forge test --match-contract TokenKatTest` rewrites them.
 contract TokenKatTest is Test {
     using MetaTxLib for MetaTxLib.MetaTransaction;
     using MetaTxLib for MetaTxLib.MetaTransfer;
@@ -52,10 +54,11 @@ contract TokenKatTest is Test {
         vm.serializeString(k, "signer", vm.toString(vm.addr(ALICE_PK)));
     }
 
-    function _check(string memory path, bytes32 typeHash, bytes32 structHash, bytes32 digest, bytes memory sig)
-        internal view
+    function _check(string memory path, bytes32 typeHash, bytes32 structHash, bytes32 digest, bytes memory sig,
+        bytes memory data) internal view
     {
         string memory onDisk = vm.readFile(path);
+        assertEq(vm.parseJsonBytes(onDisk, ".calldata"), data);
         assertEq(vm.parseJsonBytes32(onDisk, ".type_hash"), typeHash);
         assertEq(vm.parseJsonBytes32(onDisk, ".salt"), UID);
         assertEq(vm.parseJsonAddress(onDisk, ".verifying_contract"), address(tok));
@@ -75,8 +78,10 @@ contract TokenKatTest is Test {
         bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
         assertEq(digest, tok.mtxDigest(m));
         bytes memory sig = _sign(digest);
-        vm.prank(RELAYER);                                                // the vector really executes
-        tok.mtxExecute(m, sig);
+        bytes memory data = abi.encodeCall(IMetaTx.mtxExecute, (m, sig));
+        vm.prank(RELAYER);                                                // the vector really executes, as calldata
+        (bool ok,) = address(tok).call(data);
+        assertTrue(ok);
         assertEq(tok.mtxNonce(m.from, 7), 1);
 
         string memory k = "tx";
@@ -93,9 +98,10 @@ contract TokenKatTest is Test {
         vm.serializeString(k, "type_hash", vm.toString(MetaTxLib.METATX_TYPEHASH));
         vm.serializeString(k, "struct_hash", vm.toString(structHash));
         vm.serializeString(k, "digest", vm.toString(digest));
+        vm.serializeString(k, "calldata", vm.toString(data));
         string memory out = vm.serializeString(k, "signature", vm.toString(sig));
         if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT_TX);
-        _check(OUT_TX, MetaTxLib.METATX_TYPEHASH, structHash, digest, sig);
+        _check(OUT_TX, MetaTxLib.METATX_TYPEHASH, structHash, digest, sig, data);
     }
 
     function test_metaTransferKat() public {
@@ -111,8 +117,10 @@ contract TokenKatTest is Test {
         bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
         assertEq(digest, tok.mtxTransferDigest(t));
         bytes memory sig = _sign(digest);
+        bytes memory data = abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (t, sig));
         vm.prank(RELAYER);
-        tok.mtxExecuteTransfer(t, sig);
+        (bool ok,) = address(tok).call(data);
+        assertTrue(ok);
         assertEq(tok.balanceOf(address(0x5409)), 100e6);
         assertEq(tok.balanceOf(address(0xFEE)), 1e5);
 
@@ -132,8 +140,9 @@ contract TokenKatTest is Test {
         vm.serializeString(k, "type_hash", vm.toString(MetaTxLib.METATRANSFER_TYPEHASH));
         vm.serializeString(k, "struct_hash", vm.toString(structHash));
         vm.serializeString(k, "digest", vm.toString(digest));
+        vm.serializeString(k, "calldata", vm.toString(data));
         string memory out = vm.serializeString(k, "signature", vm.toString(sig));
         if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT_TRANSFER);
-        _check(OUT_TRANSFER, MetaTxLib.METATRANSFER_TYPEHASH, structHash, digest, sig);
+        _check(OUT_TRANSFER, MetaTxLib.METATRANSFER_TYPEHASH, structHash, digest, sig, data);
     }
 }
diff --git a/smartcontracts/evm/test/metatx/TradeKat.t.sol b/smartcontracts/evm/test/metatx/TradeKat.t.sol
index ea480f7..1240449 100644
--- a/smartcontracts/evm/test/metatx/TradeKat.t.sol
+++ b/smartcontracts/evm/test/metatx/TradeKat.t.sol
@@ -10,8 +10,9 @@ import {normalInit} from "../v2/helpers/V2Fixture.sol";
 
 /// KATs of the token-side DEX structs (CTR-DEX-13, CTR-DEX-02) on a real token: `trade_kat.json` holds a
 /// `TradeOrder`, its `CancelOrder` and an `InvalidateNonces`, in the token domain "SCaaS MetaToken" of a
-/// `NormalToken` clone on chain 7622 with its real `chain_uid`. (`dex_kat.json` stays the built `SCaaSDexV1`
-/// `Order` vector the node reads.) `WRITE_KAT=true forge test --match-contract TradeKatTest` rewrites the file.
+/// `NormalToken` clone on chain 7622 with its real `chain_uid`, with the relayed `mtxCancelOrder` and
+/// `mtxInvalidateNonces` calldata (both executed here). The DEX-domain `DexOrder` is `dex_order_kat.json` (DexKat.t.sol).
+/// `WRITE_KAT=true forge test --match-contract TradeKatTest` rewrites the file.
 contract TradeKatTest is Test {
     bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
     uint256 internal constant ALICE_PK = 0xA11CE;
@@ -36,6 +37,22 @@ contract TradeKatTest is Test {
         return abi.encodePacked(r, s, v);
     }
 
+    /// The relayed calldata of the cancel and the invalidate, executed (a separate frame: stack depth).
+    function _relayed(string memory k, ITradeToken.TradeOrder memory o, bytes32 h, bytes32 cancelDigest,
+        bytes32 invDigest) internal
+    {
+        bytes memory cancelData = abi.encodeCall(ITradeToken.mtxCancelOrder, (o, _sign(cancelDigest)));
+        bytes memory invData = abi.encodeCall(ITradeToken.mtxInvalidateNonces, (o.from, 7, 43, _sign(invDigest)));
+        (bool ok,) = address(tok).call(cancelData);
+        assertTrue(ok);
+        assertEq(tok.pulled(h), o.amount);
+        (ok,) = address(tok).call(invData);
+        assertTrue(ok);
+        assertEq(tok.minNonce(o.from, 7), 43);
+        vm.serializeString(k, "cancel_calldata", vm.toString(cancelData));
+        vm.serializeString(k, "invalidate_calldata", vm.toString(invData));
+    }
+
     function test_tradeKat() public {
         ITradeToken.TradeOrder memory o = ITradeToken.TradeOrder({
             from: vm.addr(ALICE_PK), receiveToken: address(0x7E57), amount: 1_000e6, receiveAmount: 2_000e6,
@@ -75,6 +92,7 @@ contract TradeKatTest is Test {
         vm.serializeString(k, "invalidate_batch", "7");
         vm.serializeString(k, "invalidate_min_nonce", "43");
         vm.serializeString(k, "invalidate_digest", vm.toString(invDigest));
+        _relayed(k, o, h, cancelDigest, invDigest);
         string memory out = vm.serializeString(k, "invalidate_signature", vm.toString(_sign(invDigest)));
         if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);
 
@@ -82,7 +100,7 @@ contract TradeKatTest is Test {
         string memory onDisk = vm.readFile(OUT);
         string[] memory keys = vm.parseJsonKeys(out, "$");
         assertEq(vm.parseJsonKeys(onDisk, "$").length, keys.length);
-        assertEq(keys.length, 20);
+        assertEq(keys.length, 22);
         for (uint256 i; i < keys.length; ++i) {
             assertEq(
                 vm.parseJsonString(onDisk, string.concat(".", keys[i])),
diff --git a/smartcontracts/evm/test/v2/DexKat.t.sol b/smartcontracts/evm/test/v2/DexKat.t.sol
new file mode 100644
index 0000000..7c3b05e
--- /dev/null
+++ b/smartcontracts/evm/test/v2/DexKat.t.sol
@@ -0,0 +1,165 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {Test} from "forge-std/Test.sol";
+import {OpenFactory} from "../../src/factory/OpenFactory.sol";
+import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
+import {NormalToken} from "../../src/metatx/NormalToken.sol";
+import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
+import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
+import {ITradeToken} from "../../src/trade/ITradeToken.sol";
+import {TradeLib} from "../../src/trade/TradeLib.sol";
+import {MockERC20} from "../helpers/Mocks.sol";
+import {UID_, normalInit} from "./helpers/V2Fixture.sol";
+
+/// KAT of the DEX side (CTR-DEX-16, -18, -02) on a real `SCaaSDex` clone on chain 7622 with its real `chain_uid`:
+/// `dex_order_kat.json` holds an outside-token maker order as a `DexOrder` in the DEX domain "SCaaS Dex", a SCaaS taker
+/// order in its token's domain, the `mtxSettle` calldata of one settlement between them, and the DEX-side
+/// `mtxCancelOrders` / `mtxInvalidateNonces` digests and calldata. Every calldata is executed here, so the node
+/// (`dex.rs`) and clientkeys encode what the contracts accept, byte for byte.
+/// `WRITE_KAT=true forge test --match-contract DexKatTest` rewrites the file.
+contract DexKatTest is Test {
+    uint256 constant ALICE_PK = 0xA11CE;
+    uint256 constant DAVE_PK = 0xDA7E;
+    address constant RELAYER = address(0xBEEF);
+    address constant TREASURY = address(0x7EA5);
+    string constant OUT = "./test/vectors/dex_order_kat.json";
+    address alice = vm.addr(ALICE_PK);
+    address dave = vm.addr(DAVE_PK);
+    NormalToken a;
+    MockERC20 usdc;
+    SCaaSDex dex;
+
+    function setUp() public {
+        vm.chainId(7622);
+        vm.warp(1_800_000_000);
+        OpenFactory f = new OpenFactory(address(this), UID_);
+        f.registerImplementation(IOpenFactory.TokenKind.NORMAL, 1,
+            address(new NormalToken(address(f), address(0), UID_, false)));
+        f.registerDexImplementation(1, address(new SCaaSDex(address(f), UID_, address(0))));
+        a = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
+            normalInit("A", "A", 6, 1e9, alice, address(0)), "a"));
+        dex = SCaaSDex(f.createDex(1, ISCaaSDex.DexConfig(address(this), 500_000, TREASURY, false), "dex"));
+        usdc = new MockERC20("USD Coin", "USDC", 6);
+        dex.setMarket(address(a), address(usdc), true);
+        usdc.mint(dave, 1e9);
+        address p = dex.puller();
+        vm.prank(dave);
+        usdc.approve(p, type(uint256).max);
+    }
+
+    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
+        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
+        return abi.encodePacked(r, s, v);
+    }
+
+    function _domainSep() internal view returns (bytes32) {
+        return keccak256(abi.encode(
+            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
+            keccak256("SCaaS Dex"), keccak256("1"), uint256(7622), address(dex), UID_));
+    }
+
+    function _tradeStruct(ITradeToken.TradeOrder memory o) internal pure returns (bytes32) {
+        return keccak256(abi.encode(TradeLib.TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount,
+            o.minFill, o.fee, o.relayer, o.dex, o.destination, o.flags, o.batch, o.nonce, o.validUntil));
+    }
+
+    /// Dave (maker, outside token) sells 2000 USDC for >= 1000 A; Alice (taker, SCaaS) sells 500 A for >= 1000 USDC.
+    function _orders() internal view returns (ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t) {
+        m = ITradeToken.TradeOrder({
+            from: dave, receiveToken: address(a), amount: 2000e6, receiveAmount: 1000e6, minFill: 0, fee: 3_000,
+            relayer: RELAYER, dex: address(dex), destination: address(0), flags: 0, batch: 1, nonce: 3,
+            validUntil: 1_800_000_300
+        });
+        t = ITradeToken.TradeOrder({
+            from: alice, receiveToken: address(usdc), amount: 500e6, receiveAmount: 1000e6, minFill: 0, fee: 3_000,
+            relayer: RELAYER, dex: address(dex), destination: address(0x5E11), flags: 1, batch: 2, nonce: 9,
+            validUntil: 1_800_000_300
+        });
+    }
+
+    /// One settlement: Dave fills half (1000 USDC, receives ceil(1000 * 1000 / 2000) = 500 A), Alice all of hers.
+    function _settle(string memory k, ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t, bytes32 hm)
+        internal
+    {
+        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](1);
+        ss[0].ref = keccak256("scaas.kat.settlement");
+        ss[0].taker = ISCaaSDex.Leg(address(a), t, _sign(ALICE_PK, a.tradeOrderDigest(t)), 500e6);
+        ss[0].makers = new ISCaaSDex.Leg[](1);
+        ss[0].makers[0] = ISCaaSDex.Leg(address(usdc), m, _sign(DAVE_PK, hm), 1000e6);
+        bytes memory settleData = abi.encodeCall(ISCaaSDex.mtxSettle, (ss));
+        vm.prank(RELAYER);
+        (bool ok, bytes memory ret) = address(dex).call(settleData);   // the vectors really execute
+        assertTrue(ok);
+        assertTrue(abi.decode(ret, (bool[]))[0]);
+        assertEq(usdc.balanceOf(address(0x5E11)), 1000e6 - 3e6);         // fee ceil(1000e6 * 3000 / 1e6)
+        assertEq(a.balanceOf(dave), 500e6 - 1.5e6);
+        assertEq(dex.pulled(hm), 1000e6);
+        vm.serializeString(k, "settle_calldata", vm.toString(settleData));
+    }
+
+    /// The DEX-side cancel closes Dave's remainder; the DEX-side invalidate raises his lane 1 to 5.
+    function _cancels(string memory k, ITradeToken.TradeOrder memory m, bytes32 hm, bytes32 domainSep) internal {
+        bytes32 cancelDigest = dex.cancelOrderDigest(hm);
+        assertEq(cancelDigest, keccak256(abi.encodePacked(hex"1901", domainSep,
+            keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, hm)))));
+        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](1);
+        os[0] = ISCaaSDex.DexOrder(address(usdc), m);
+        bytes[] memory sigs = new bytes[](1);
+        sigs[0] = _sign(DAVE_PK, cancelDigest);
+        bytes memory cancelData = abi.encodeCall(ISCaaSDex.mtxCancelOrders, (os, sigs));
+        (bool ok,) = address(dex).call(cancelData);
+        assertTrue(ok);
+        assertEq(dex.pulled(hm), m.amount);
+        bytes32 invDigest = dex.invalidateNoncesDigest(dave, 1, 5);
+        assertEq(invDigest, keccak256(abi.encodePacked(hex"1901", domainSep,
+            keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, dave, uint256(1), uint256(5))))));
+        bytes memory invData = abi.encodeCall(ISCaaSDex.mtxInvalidateNonces, (dave, 1, 5, _sign(DAVE_PK, invDigest)));
+        (ok,) = address(dex).call(invData);
+        assertTrue(ok);
+        assertEq(dex.minNonce(dave, 1), 5);
+        vm.serializeString(k, "cancel_digest", vm.toString(cancelDigest));
+        vm.serializeString(k, "cancel_orders_calldata", vm.toString(cancelData));
+        vm.serializeString(k, "invalidate_digest", vm.toString(invDigest));
+        vm.serializeString(k, "invalidate_calldata", vm.toString(invData));
+    }
+
+    function test_dexKat() public {
+        (ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t) = _orders();
+        bytes32 domainSep = _domainSep();
+        bytes32 dexOrderStruct = keccak256(abi.encode(
+            keccak256("DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,"
+                "uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,"
+                "address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"),
+            address(usdc), _tradeStruct(m)));
+        bytes32 hm = keccak256(abi.encodePacked(hex"1901", domainSep, dexOrderStruct));
+        assertEq(hm, dex.dexOrderDigest(address(usdc), m));
+
+        string memory k = "dex";
+        vm.serializeString(k, "chain_id", "7622");
+        vm.serializeString(k, "salt", vm.toString(UID_));
+        vm.serializeString(k, "dex", vm.toString(address(dex)));
+        vm.serializeString(k, "dex_domain_separator", vm.toString(domainSep));
+        vm.serializeString(k, "token", vm.toString(address(a)));
+        vm.serializeString(k, "outside_token", vm.toString(address(usdc)));
+        vm.serializeString(k, "maker_order_abi", vm.toString(abi.encode(m)));
+        vm.serializeString(k, "dex_order_struct_hash", vm.toString(dexOrderStruct));
+        vm.serializeString(k, "dex_order_hash", vm.toString(hm));
+        vm.serializeString(k, "taker_order_abi", vm.toString(abi.encode(t)));
+        vm.serializeString(k, "taker_order_hash", vm.toString(a.tradeOrderDigest(t)));
+        _settle(k, m, t, hm);
+        _cancels(k, m, hm, domainSep);
+        string memory out = vm.serializeString(k, "relayer", vm.toString(RELAYER));
+        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);
+
+        string memory onDisk = vm.readFile(OUT);
+        string[] memory keys = vm.parseJsonKeys(out, "$");
+        assertEq(vm.parseJsonKeys(onDisk, "$").length, keys.length);
+        assertEq(keys.length, 17);
+        for (uint256 i; i < keys.length; ++i) {
+            assertEq(
+                vm.parseJsonString(onDisk, string.concat(".", keys[i])),
+                vm.parseJsonString(out, string.concat(".", keys[i])), keys[i]);
+        }
+    }
+}
diff --git a/smartcontracts/evm/test/vectors/dex_order_kat.json b/smartcontracts/evm/test/vectors/dex_order_kat.json
new file mode 100644
index 0000000..84d2be5
--- /dev/null
+++ b/smartcontracts/evm/test/vectors/dex_order_kat.json
@@ -0,0 +1,19 @@
+{
+  "cancel_digest": "0x997e0117fb3d546ce099a4f9896bd242cdd17f87b459db15c6711c63168d81e9",
+  "cancel_orders_calldata": "0x2de621d20000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000000010000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a9000000000000000000000000c6f06be7b01a7c8a72f9c67299e116dea6755ed20000000000000000000000007c6ba371836af59c73c842cc3e6a755f277589ec0000000000000000000000000000000000000000000000000000000077359400000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000870782cde6f859ff462fe6ee225e7e422f602490000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000006b49d32c00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004146a9fd67db8657aa150889fcd0ea7b5e4418ae9d42817afecb4a1d3d811df7226bee2e7c7b0eede0d0723d6a9d308441f8da78de73d0f90212c280cae156b6d21c00000000000000000000000000000000000000000000000000000000000000",
+  "chain_id": "7622",
+  "dex": "0x0870782cDe6F859fF462FE6Ee225E7e422f60249",
+  "dex_domain_separator": "0xc7f0fa7510222b829c05c2fe8b6306c1aa96655ad89bc4eaefc508c949ed47f9",
+  "dex_order_hash": "0x79a1f662a118c7c1c146dec9944884a2719b589d96c6ba339666a09a4c68d2bd",
+  "dex_order_struct_hash": "0x7b53d6b9cc7ec30949458787389c656e52514b1b25c84ee8516a6b1bc7ef30e3",
+  "invalidate_calldata": "0xdbac32d0000000000000000000000000c6f06be7b01a7c8a72f9c67299e116dea6755ed20000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041be4bc5fb7b5aacfb317c23ca7ba4659f0761e8a6fce40da8bd911e0ebe563d496a5e636af60e526fe95136f29f695c594cf336e06ecb3f8524a83349148f71831c00000000000000000000000000000000000000000000000000000000000000",
+  "invalidate_digest": "0x0c69b881bd15d891124f5219439904b760372710261c43d31497b9f9c63db3bf",
+  "maker_order_abi": "0x000000000000000000000000c6f06be7b01a7c8a72f9c67299e116dea6755ed20000000000000000000000007c6ba371836af59c73c842cc3e6a755f277589ec0000000000000000000000000000000000000000000000000000000077359400000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000870782cde6f859ff462fe6ee225e7e422f602490000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000006b49d32c",
+  "outside_token": "0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9",
+  "relayer": "0x000000000000000000000000000000000000bEEF",
+  "salt": "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464",
+  "settle_calldata": "0xb0955dd600000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002057ae592c697de3ae9b853bd7e26e841602a2bb822e5c7fa7d4074e6265892823000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002e00000000000000000000000007c6ba371836af59c73c842cc3e6a755f277589ec000000000000000000000000e05fcc23807536bee418f142d19fa0d21bb0cff70000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a9000000000000000000000000000000000000000000000000000000001dcd6500000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000870782cde6f859ff462fe6ee225e7e422f602490000000000000000000000000000000000000000000000000000000000005e11000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000006b49d32c0000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000001dcd6500000000000000000000000000000000000000000000000000000000000000004160069348a8a4071430e6747289cbcfa6c8cd929aebca4f53295f2e5e39c496cd397ad60b14065740833e414457085b0d61f5568b86f4f9935d0db2911072a5281b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a9000000000000000000000000c6f06be7b01a7c8a72f9c67299e116dea6755ed20000000000000000000000007c6ba371836af59c73c842cc3e6a755f277589ec0000000000000000000000000000000000000000000000000000000077359400000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000870782cde6f859ff462fe6ee225e7e422f602490000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000006b49d32c0000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000000000414c8ac53a85be8f890d023d7658b021b13667967b66f76a2e176a8c11c570ac2e320f864d8bc102805d6f7ef071eb7b65a6bd2ad45833da3779ca8f884407c3c31c00000000000000000000000000000000000000000000000000000000000000",
+  "taker_order_abi": "0x000000000000000000000000e05fcc23807536bee418f142d19fa0d21bb0cff70000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a9000000000000000000000000000000000000000000000000000000001dcd6500000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000870782cde6f859ff462fe6ee225e7e422f602490000000000000000000000000000000000000000000000000000000000005e11000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000006b49d32c",
+  "taker_order_hash": "0xb972577efc95ec2e6fe99820c75eed5860b02c199d17f00d548ea63cb90a186c",
+  "token": "0x7C6ba371836Af59c73c842Cc3E6A755F277589ec"
+}
\ No newline at end of file
diff --git a/smartcontracts/evm/test/vectors/metatransfer_kat.json b/smartcontracts/evm/test/vectors/metatransfer_kat.json
index 24e19ca..c292455 100644
--- a/smartcontracts/evm/test/vectors/metatransfer_kat.json
+++ b/smartcontracts/evm/test/vectors/metatransfer_kat.json
@@ -1,5 +1,6 @@
 {
   "batch": "7405258708504342445307474482762115553420430596304838433236153892639744162364",
+  "calldata": "0x90706250000000000000000000000000e05fcc23807536bee418f142d19fa0d21bb0cff700000000000000000000000000000000000000000000000000000000000054090000000000000000000000000000000000000000000000000000000005f5e10017b3a4b47b86824218fba3a68c90cd53ea80198f8a5efef1a8775864b2cb5eca105f3a577d7b0eff979ea356ebfca2c588331f8c724e04a079927cefc04f7a3c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b49d32c0000000000000000000000000000000000000000000000000000000000000023000000000000000000000000000000000000000000000000000000000000beef00000000000000000000000000000000000000000000000000000000000186a00000000000000000000000000000000000000000000000000000000000000fee00000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000041d1ec64d13f648b2198fe18ab1d8277211da0f23ee03127f0827acaf24872a8351fc5e09041fe7e7814cc398dbf3fd19fcb407b634c46e086e7c6eb96051aa8831b00000000000000000000000000000000000000000000000000000000000000",
   "chain_id": "7622",
   "digest": "0x42720219e861b12cb5e822ce343921c1aef87a83ffe14e2fbf276ff7c17e3543",
   "domain_name": "SCaaS MetaToken",
diff --git a/smartcontracts/evm/test/vectors/metatx_kat.json b/smartcontracts/evm/test/vectors/metatx_kat.json
index 82c0f25..2347d07 100644
--- a/smartcontracts/evm/test/vectors/metatx_kat.json
+++ b/smartcontracts/evm/test/vectors/metatx_kat.json
@@ -1,5 +1,6 @@
 {
   "batch": "7",
+  "calldata": "0x58404dde000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000e05fcc23807536bee418f142d19fa0d21bb0cff7000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b49d32c0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000beef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fee0000000000000000000000000000000000000000000000000000000000000024cfdd7aea000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004115614a77cc0728d945506eb23c7ca339d61cea682283964193c0f8aeec849d574eabfcf485537a6f00630763072eb662b452d055427013df10cce3e9bd23f0451b00000000000000000000000000000000000000000000000000000000000000",
   "chain_id": "7622",
   "data": "0xcfdd7aea000000000000000000000000000000000000000000000000000000000000002a",
   "digest": "0xc48ce070181907bf93b1f7969a4f99d85239bd9e61a99e9123440e7359660694",
diff --git a/smartcontracts/evm/test/vectors/trade_kat.json b/smartcontracts/evm/test/vectors/trade_kat.json
index 2479ef8..2f883c8 100644
--- a/smartcontracts/evm/test/vectors/trade_kat.json
+++ b/smartcontracts/evm/test/vectors/trade_kat.json
@@ -1,4 +1,5 @@
 {
+  "cancel_calldata": "0x93cb3e81000000000000000000000000e05fcc23807536bee418f142d19fa0d21bb0cff70000000000000000000000000000000000000000000000000000000000007e57000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000773594000000000000000000000000000000000000000000000000000000000023c346000000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000000000000000de7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000006b49d32c00000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000041cef7a9c5593ff3bfbad20a3e8aaa1effd1e354211cceb6a8fe73c3bde12827bc02086d4a152cd0091b7b76e28d72f1cdc79df5dbc19300bfc43f07ed14e600d01b00000000000000000000000000000000000000000000000000000000000000",
   "cancel_digest": "0x69a37e8615cde038e31c3e44f32c936129db9c1c86ebd42e37a2a28fe14895e9",
   "cancel_signature": "0xcef7a9c5593ff3bfbad20a3e8aaa1effd1e354211cceb6a8fe73c3bde12827bc02086d4a152cd0091b7b76e28d72f1cdc79df5dbc19300bfc43f07ed14e600d01b",
   "cancel_type_hash": "0xe70fd60b1c6c2a2394fdccb638d1e84b9233a8fa520436c8cf500b6d5b62cd64",
@@ -7,6 +8,7 @@
   "domain_separator": "0x5308595090be14cab58d51d1a29c78dc374e4e3b21743fd647b1978298615128",
   "domain_version": "1",
   "invalidate_batch": "7",
+  "invalidate_calldata": "0xdbac32d0000000000000000000000000e05fcc23807536bee418f142d19fa0d21bb0cff70000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000002b00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041156d5bc6921251772e5f347405863061d8763c361fc6b2bae4c6afec9c47e1c2699a0c10562b1d34c7cbcd0f4ca830e326659b87972d800ddf8fb8682ee162b11c00000000000000000000000000000000000000000000000000000000000000",
   "invalidate_digest": "0x62c720540c91ee6e7b1d28a2e1fc34efd9312d2209b174ed58e1f415c0cfb408",
   "invalidate_min_nonce": "43",
   "invalidate_signature": "0x156d5bc6921251772e5f347405863061d8763c361fc6b2bae4c6afec9c47e1c2699a0c10562b1d34c7cbcd0f4ca830e326659b87972d800ddf8fb8682ee162b11c",
``````


### Task 2: The node's meta-tx path on `MetaTransaction` / `MetaTransfer` (salted), the mesh EVM body, the Hedera KAT v3, demo tokens from `OpenFactory`

The node relays the built tree: `abi.rs` copies the two structs, `TradeOrder` and the token interface (`IToken`:
`mtxNonce`, `mtxDigest`, `mtxTransferDigest`, `mtxExecute`, `mtxExecuteTransfer`, `mtxSelectors`, `chainUid`,
`supportedModes`, events, errors) and `IMandateWallet`'s errors (a `call` job's revert names `StaleEpoch` for the
client); `metatx.rs` is rewritten around `enum Mtx { Call, Transfer }` (N1) with the salted `Domain` (N2: `salt =
chain_uid`), the canonical zeroing of unbound `relayer`/`feeRecipient`, digest, struct hash and calldata, each checked
against the Task 1 KATs. The Odoo job carries `struct` and `metatx`; the gateway body is `{chain, token, struct, m,
signature}`; the indexer, drift check and adapters read `IToken`. The mesh EVM body becomes `{domain, struct, meta_tx,
signature, sig_kind}` with the salt from the chain's `chain_uid` (`UNKNOWN_CHAIN` without one, N10) and the vectors are
regenerated. The Hedera KAT becomes a v3 `NormalToken` clone on chain 296 with an ED25519 signature over the v3
digest (N11), the v1 KAT and its generator move to `legacy/p5/`. The deploy scripts make two demo tokens from
`OpenFactory.createToken` (`_demoTokens`, N13): the e2e never deploys a `MetaToken` again. The e2e suites move to
`MetaTransfer`.

**Files:** modify `scaas-node/src/{abi,adapter,chain,drift,gateway,indexer,metatx,odoo,submit}.rs`,
`scaas-node/src/adapters/{evm,hedera}.rs`, `scaas-node/src/mesh/{accept,digest}.rs`,
`scaas-node/tests/{e2e,e2e_hedera,fuzz,mesh_vectors}.rs`, `scaas-node/tests/vectors/mesh-envelope-v1.2.json`
(regenerated), `smartcontracts/evm/script/{Deploy.s.sol,DeployBase.sol}`, `smartcontracts/evm/script/hedera/DeployHedera.s.sol`,
`smartcontracts/evm/test/hedera/{HederaKat.t.sol,gen_hedera_kat.py}`, `smartcontracts/evm/test/vectors/hedera_kat.json`;
move the v1 Hedera KAT to `smartcontracts/evm/legacy/p5/test/{hedera/HederaKat.t.sol,hedera/gen_hedera_kat.py,vectors/hedera_kat.json}`.

- [ ] **Step 1: Back up the v1 Hedera KAT.**
  ```bash
  cd smartcontracts/evm && mkdir -p legacy/p5/test/hedera legacy/p5/test/vectors
  /usr/bin/git show HEAD:smartcontracts/evm/test/hedera/HederaKat.t.sol > legacy/p5/test/hedera/HederaKat.t.sol
  /usr/bin/git show HEAD:smartcontracts/evm/test/hedera/gen_hedera_kat.py > legacy/p5/test/hedera/gen_hedera_kat.py
  /usr/bin/git show HEAD:smartcontracts/evm/test/vectors/hedera_kat.json > legacy/p5/test/vectors/hedera_kat.json
  ```
  (the copies are byte-identical to `main`; the diff below shows them as copies).
- [ ] **Step 2: Apply the diff below** (the mesh vector file is not shown: Step 4 writes it).
- [ ] **Step 3: The Hedera KAT.** `WRITE_KAT=true ../../scripts/capped forge test --match-contract HederaKatTest` writes the
  unsigned fields, `python3 test/hedera/gen_hedera_kat.py` signs them (needs `cryptography`), then
  `../../scripts/capped forge test --match-contract HederaKatTest` passes; `hedera_kat.json` equals the diff.
- [ ] **Step 4: Regenerate the mesh vectors.** `cd scaas-node && ../scripts/capped cargo test --test mesh_vectors -- --ignored regenerate`;
  sha256 of `tests/vectors/mesh-envelope-v1.2.json`: `2940d0d21c84cfb389493284b92d0ee461132e0eaa91730d9398b85f80e11c9c`.
- [ ] **Step 5: Gates.** `../../scripts/capped forge build` (full), then in `scaas-node`: `cargo test --lib` 242 passed;
  `cargo test --test mesh_vectors --test fuzz` 4 + 1 passed (1 ignored: `regenerate`); clippy clean; `cargo test --test e2e -- --ignored --test-threads=1`
  4/4; `cargo test --test e2e_hedera -- --ignored` 1/1; forge `forge test` 1002 passed.
- [ ] **Step 6: Commit** `P5 T2: node meta-tx path on MetaTransaction/MetaTransfer, salted domains, mesh EVM body, Hedera KAT v3, demo tokens from OpenFactory`.

``````diff
diff --git a/scaas-node/src/abi.rs b/scaas-node/src/abi.rs
index ba02280..d31682a 100644
--- a/scaas-node/src/abi.rs
+++ b/scaas-node/src/abi.rs
@@ -1,22 +1,52 @@
-//! ABI — chép chữ ký từ `smartcontracts/evm/src`, không suy luận. Sai một `indexed` là sai topic.
+//! ABI — copied from `smartcontracts/evm/src` (`IMetaTx`, `IERC20MetaTx`, `IERC20Payment`, `ITradeToken`, `MetaTxLib`,
+//! `MandateWallet`), never inferred: one wrong `indexed` is one wrong topic. Pinned by the forge KATs
+//! (`metatx_kat.json`, `metatransfer_kat.json`, `trade_kat.json`: digests and relayed calldata).
 use alloy::sol;
 use alloy::sol_types::SolInterface;
 
 sol! {
+    /// `MetaTxLib.MetaTransaction` (CTR-MTX-15): the signed call of one of the contract's own allowlisted functions.
     #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
     struct MetaTransaction {
-        address from; address to; uint256 value; bytes data;
-        uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode;
+        address from; bytes data; uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode;
         address relayer; uint256 fee; address feeRecipient;
     }
 
+    /// `MetaTxLib.MetaTransfer` (CTR-MTX-23): a token transfer (`entryRef = 0`) or payment.
+    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
+    struct MetaTransfer {
+        address from; address to; uint256 value; bytes32 entryRef; uint256 batch; uint256 nonce; uint256 validUntil;
+        uint32 mode; address relayer; uint256 fee; address feeRecipient;
+    }
+
+    /// `ITradeToken.TradeOrder` (CTR-DEX-13): signed in the sell token's domain (a `DexOrder` for an outside token).
+    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
+    struct TradeOrder {
+        address from; address receiveToken; uint256 amount; uint256 receiveAmount; uint256 minFill; uint256 fee;
+        address relayer; address dex; address destination; uint8 flags; uint256 batch; uint256 nonce;
+        uint256 validUntil;
+    }
+
+    /// Every SCaaS contract on `MetaTxBase` (`IMetaTx`) plus the token surface the node reads or relays.
     #[derive(Debug)]
-    interface IMetaToken {
-        function executeMetaTransaction(MetaTransaction m, bytes signature) external returns (bool);
-        function metaTxDigest(MetaTransaction m) external view returns (bytes32);
-        function metaNonce(address from, uint256 batch) external view returns (uint256);
+    interface IToken {
+        function mtxNonce(address from, uint256 batch) external view returns (uint256);
+        function mtxDigest(MetaTransaction m) external view returns (bytes32);
+        function mtxTransferDigest(MetaTransfer t) external view returns (bytes32);
+        function mtxExecute(MetaTransaction m, bytes signature) external returns (bytes);
+        function mtxExecuteTransfer(MetaTransfer t, bytes signature) external returns (bool);
+        function mtxSelectors() external view returns (bytes4[] selectors, uint8[] feeClass, uint8[] amountArg);
+        function chainUid() external view returns (bytes32);
+        function supportedModes() external view returns (uint32);
         function balanceOf(address who) external view returns (uint256);
         function transfer(address to, uint256 value) external returns (bool);
+        function mtxCancelOrder(TradeOrder o, bytes sig) external;
+        function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes sig) external;
+        function tradeOrderDigest(TradeOrder o) external view returns (bytes32);
+        function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
+        function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
+        function pulled(bytes32 orderHash) external view returns (uint256);
+        function minNonce(address from, uint256 batch) external view returns (uint256);
         event MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch,
             uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
         event PaymentSettled(address indexed from, address indexed to, uint256 amount, uint256 feeAmount,
@@ -27,48 +57,63 @@ sol! {
         error MetaTxBadSignature();
         error MetaTxUnauthorizedRelayer(address allowed, address caller);
         error MetaTxUnknownMode(uint32 mode);
+        error MtxSelectorNotAllowed(bytes4 selector);
+        error MtxDataShape(bytes4 selector);
+        error MtxFeeClass(bytes4 selector, uint32 mode);
+        error Reentrancy();
+        error SelfSender();
         error MetaTxInsufficientForFee(uint256 needed, uint256 available);
-        error MetaTxUnknownOp(bytes4 op);
         error PayToZero();
-        error TradeLegNotRestricted();
-        error FeeExceedsCap(uint256 feeAmount, uint256 cap);
-        error FeeRecipientRequired();
+        error TransferToSelf();
+        error FeeRecipientIsPayee();
         error ModeFeeInvalid(uint32 mode);
         error ModeUnknownBits(uint32 mode);
+        error SigCheckGasStarved(uint256 cap, uint256 gasLeft);
+        error NotDex(address caller);
+        error DexNotContract(address dex);
+        error SelfOrder(bytes32 orderHash);
+        error WrongRelayer(bytes32 orderHash, address submitter);
+        error OrderExpired(bytes32 orderHash);
+        error NonceInvalidated(bytes32 orderHash);
+        error BadFlags(bytes32 orderHash);
+        error ZeroAmount(bytes32 orderHash);
+        error BadMinFill(bytes32 orderHash);
+        error FeeAboveCap(bytes32 orderHash);
+        error OrderClosed(bytes32 orderHash);
+        error ZeroFill(bytes32 orderHash);
+        error Overfill(bytes32 orderHash);
+        error BelowMinFill(bytes32 orderHash);
+        error PriceLimit(bytes32 orderHash);
+        error FeeAboveSigned(bytes32 orderHash);
+        error EscrowFillShape(bytes32 orderHash);
+        error MinNonceNotIncreasing(uint256 current, uint256 requested);
+        error MinNonceAboveCap(uint256 requested);
     }
 
+    /// `MandateWallet` errors (CTR-ACC-06/07): a `call` job's revert reason names them, so the client re-reads
+    /// `epoch(token)` and re-signs on `StaleEpoch`.
     #[derive(Debug)]
-    struct Leg { address token; MetaTransaction m; bytes sig; }
-
-    #[derive(Debug)]
-    interface IMetaTxDex {
-        function settle(Leg a, Leg b) external;
-        event TradeSettled(address indexed partyA, address indexed partyB, address tokenA, address tokenB,
-            uint256 valueA, uint256 valueB);
-        error NotATradeLeg();
-        error SameToken();
-        error SameParty();
-        error CounterTokenMismatch();
-        error PriceNotMet(uint256 got, uint256 min);
-        error CounterpartyMismatch();
-        error LegNotRoutedHere();
-        error FeeWouldStick();
-        error DeltaMismatch(address token, uint256 got, uint256 expected);
-    }
-
-    #[derive(Debug)]
-    interface IOpenFactory {
-        function createMetaToken(uint64 version, address underlying, bytes initData, bytes32 salt)
-            external returns (address token);
+    interface IMandateWallet {
+        error NotOwner();
+        error NotDelegate();
+        error NoMandate();
+        error MandateExpired();
+        error PayeeNotAllowed(address payee);
+        error OverPaymentCap(uint256 amount, uint256 cap);
+        error OverPeriodCap(uint256 wouldSpend, uint256 cap);
+        error RefAlreadyPaid(bytes32 entryRef);
+        error StaleEpoch(uint64 current, uint64 signed);
+        error CallFailed(bytes reason);
+        error PayFailed();
     }
 }
 
-/// Tên lỗi đọc được cho `last_error` ở Odoo; hex thô nếu không nhận ra.
+/// Readable error name for `last_error` on the client; raw hex when it is none of ours.
 pub fn decode_revert(data: &[u8]) -> String {
-    if let Ok(e) = IMetaToken::IMetaTokenErrors::abi_decode(data) {
+    if let Ok(e) = IToken::ITokenErrors::abi_decode(data) {
         return format!("{e:?}");
     }
-    if let Ok(e) = IMetaTxDex::IMetaTxDexErrors::abi_decode(data) {
+    if let Ok(e) = IMandateWallet::IMandateWalletErrors::abi_decode(data) {
         return format!("{e:?}");
     }
     format!("revert 0x{}", alloy::hex::encode(data))
@@ -82,10 +127,12 @@ mod tests {
 
     #[test]
     fn known_errors_are_named() {
-        let e = IMetaToken::MetaTxBadNonce { expected: U256::from(1), got: U256::ZERO }.abi_encode();
+        let e = IToken::MetaTxBadNonce { expected: U256::from(1), got: U256::ZERO }.abi_encode();
         assert!(decode_revert(&e).contains("MetaTxBadNonce"));
-        let e = IMetaTxDex::FeeWouldStick {}.abi_encode();
-        assert!(decode_revert(&e).contains("FeeWouldStick"));
+        let e = IMandateWallet::StaleEpoch { current: 2, signed: 1 }.abi_encode();
+        assert!(decode_revert(&e).starts_with("StaleEpoch"), "{}", decode_revert(&e));
+        let e = IToken::MinNonceNotIncreasing { current: U256::from(5), requested: U256::from(5) }.abi_encode();
+        assert!(decode_revert(&e).starts_with("MinNonceNotIncreasing("));
         assert!(decode_revert(&[1, 2, 3]).starts_with("revert 0x"));
     }
 }
diff --git a/scaas-node/src/adapter.rs b/scaas-node/src/adapter.rs
index 86ee669..4508e9e 100644
--- a/scaas-node/src/adapter.rs
+++ b/scaas-node/src/adapter.rs
@@ -123,7 +123,7 @@ pub trait ChainAdapter: Send + Sync {
     }
     /// R80: `Some(true)` ⇔ nonce lane của chủ thể đã qua nonce của op (ai đó đã dùng nó). `Ok(None)` = không biết
     /// ⇒ không bao giờ dừng job vì nó: mọi loại op mà replay guard không phải nonce lane (review M6). v1 chỉ trả lời
-    /// cho `pay` (và meta-tx Hedera qua `metaNonce`). Lỗi RPC ⇒ `Err`: không gửi lại vòng này (fail closed).
+    /// cho `pay` (và meta-tx Hedera qua `mtxNonce`). Lỗi RPC ⇒ `Err`: không gửi lại vòng này (fail closed).
     async fn op_consumed(&self, _job: &Job) -> Result<Option<bool>> {
         Ok(None)
     }
diff --git a/scaas-node/src/adapters/evm.rs b/scaas-node/src/adapters/evm.rs
index 896fe8d..2342e9d 100644
--- a/scaas-node/src/adapters/evm.rs
+++ b/scaas-node/src/adapters/evm.rs
@@ -11,7 +11,7 @@ use anyhow::{anyhow, Result};
 use async_trait::async_trait;
 use serde_json::{json, Value};
 
-use crate::abi::IMetaToken;
+use crate::abi::IToken;
 use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Signed, TxStatus};
 use crate::chain::{Chain, SimError};
 use crate::config::ChainCfg;
@@ -148,8 +148,8 @@ impl ChainAdapter for EvmAdapter {
             return Ok(vec![]);
         }
         let f = Filter::new().from_block(from).to_block(to).address(addrs).event_signature(vec![
-            IMetaToken::PaymentSettled::SIGNATURE_HASH,
-            IMetaToken::MetaTransactionExecuted::SIGNATURE_HASH,
+            IToken::PaymentSettled::SIGNATURE_HASH,
+            IToken::MetaTransactionExecuted::SIGNATURE_HASH,
         ]);
         Ok(self.chains[0].primary().get_logs(&f).await?.iter().filter_map(encode_event).collect())
     }
diff --git a/scaas-node/src/adapters/hedera.rs b/scaas-node/src/adapters/hedera.rs
index 0c3213d..388d2fd 100644
--- a/scaas-node/src/adapters/hedera.rs
+++ b/scaas-node/src/adapters/hedera.rs
@@ -1,4 +1,4 @@
-//! Hedera HSCS qua Hedera JSON-RPC Relay (R63). Contract là Solidity (`HederaMetaToken`), tx là tx Ethereum
+//! Hedera HSCS qua Hedera JSON-RPC Relay (R63). Contract là Solidity (the token kinds with `IS_HEDERA`), tx là tx Ethereum
 //! ký ECDSA từ lane (alias EVM, `m/44'/3030'/0'/0/i`), nên phần lớn đi nhờ `EvmAdapter`. Riêng Hedera:
 //!
 //! - **R6-1**: không mempool — tx vào đồng thuận trong vài giây hoặc bị từ chối; nonce tương lai có thể tới
@@ -148,10 +148,10 @@ impl ChainAdapter for HederaAdapter {
         self.inner.lanes()
     }
 
-    /// R80: meta-tx ⇒ `metaNonce(from, batch)` (mọi op của meta-tx dùng chung nonce này); job `call` ⇒ không biết.
+    /// R80: meta-tx ⇒ `mtxNonce(from, batch)` (both structs share the lane); job `call` ⇒ không biết.
     async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
         let Some(m) = work_from_job(job).ok().and_then(|w| w.meta) else { return Ok(None) };
-        Ok(Some(self.inner.lane(0)?.meta_nonce(m.token, m.from, m.batch).await? > m.nonce))
+        Ok(Some(self.inner.lane(0)?.mtx_nonce(m.token, m.from, m.batch).await? > m.nonce))
     }
 
     async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
@@ -281,8 +281,8 @@ mod tests {
         balance: &'static str,
         receipt: Value,
         send_error: Option<Value>,
-        /// `eth_call` trả về word này (mô phỏng bỏ qua nó; `metaNonce` đọc nó).
-        meta_nonce: u64,
+        /// `eth_call` trả về word này (mô phỏng bỏ qua nó; `mtxNonce` đọc nó).
+        mtx_nonce: u64,
         sent: Vec<String>,
         jobs: Vec<Value>,
         reports: Vec<Value>,
@@ -296,7 +296,7 @@ mod tests {
         let ok = |r: Value| json!({"jsonrpc": "2.0", "id": id, "result": r});
         axum::Json(match b["method"].as_str().unwrap_or_default() {
             "eth_getBalance" => ok(json!(n.balance)),
-            "eth_call" => ok(json!(format!("0x{:064x}", n.meta_nonce))),
+            "eth_call" => ok(json!(format!("0x{:064x}", n.mtx_nonce))),
             "eth_estimateGas" => ok(json!("0x186a0")),
             "eth_gasPrice" => ok(json!(format!("0x{GAS_PRICE:x}"))),
             "eth_getTransactionCount" => ok(json!("0x7")),
@@ -330,9 +330,10 @@ mod tests {
     fn job(valid_until: u64) -> Value {
         let z = format!("{:#x}", Address::ZERO);
         json!({"id": 7, "token": format!("{:#x}", Address::repeat_byte(0x70)), "signature": format!("0x{}", "ab".repeat(64)),
+               "struct": "transfer",
                "metatx": {"from": format!("{:#x}", Address::repeat_byte(1)), "to": format!("{:#x}", Address::repeat_byte(2)),
-                          "value": "1", "data": "0x", "batch": "1", "nonce": "0", "validUntil": valid_until.to_string(),
-                          "mode": 0, "relayer": z, "fee": "0", "feeRecipient": z}})
+                          "value": "1", "entryRef": format!("{:#x}", B256::ZERO), "batch": "1", "nonce": "0",
+                          "validUntil": valid_until.to_string(), "mode": 0, "relayer": z, "fee": "0", "feeRecipient": z}})
     }
 
     /// Chạy MỘT `lane_step` của `HederaAdapter` thật; trả các `chain_state` đã báo và trạng thái mạng giả.
@@ -385,10 +386,10 @@ mod tests {
         assert_eq!(step(net, now() + 600).await.0, ["signed", "broadcast", "reverted"]);
     }
 
-    /// R80/H3: revert vì relayer khác đã dùng nonce chủ thể (`metaNonce` đã qua) ⇒ `consumed`, không `reverted`.
+    /// R80/H3: revert vì relayer khác đã dùng nonce chủ thể (`mtxNonce` đã qua) ⇒ `consumed`, không `reverted`.
     #[tokio::test]
     async fn revert_after_a_lost_race_is_consumed() {
-        let net = Net { balance: "0x1", receipt: receipt("0x0", "CONTRACT_REVERT_EXECUTED"), meta_nonce: 1, ..Default::default() };
+        let net = Net { balance: "0x1", receipt: receipt("0x0", "CONTRACT_REVERT_EXECUTED"), mtx_nonce: 1, ..Default::default() };
         assert_eq!(step(net, now() + 600).await.0, ["signed", "broadcast", "consumed"]);
     }
 
@@ -415,34 +416,33 @@ mod tests {
         assert_eq!(states, ["queued"]);
     }
 
-    /// Cùng vector với forge (`HederaKat.t.sol`) và Odoo (`test_hedera.py`): digest EIP-712 và chữ ký ed25519
-    /// thật của tài khoản 0.0.1234567 trên đúng 32 byte đó (phép HIP-632 kiểm).
+    /// The Hedera vector (`HederaKat.t.sol` + `gen_hedera_kat.py`): the salted `MetaTransfer` digest of an `IS_HEDERA`
+    /// token and a real ed25519 signature of the account 0.0.1234567 over those 32 bytes (what HIP-632 checks).
     #[test]
     fn kat_digest_and_ed25519_signature() {
-        use crate::metatx::{digest, Domain, WireMetaTx};
+        use crate::metatx::{Domain, Mtx};
         use ed25519_dalek::{Signature, Verifier, VerifyingKey};
         let k: Value = serde_json::from_str(KAT).unwrap();
         let s = |f: &str| k[f].as_str().unwrap().to_string();
-        let wire: WireMetaTx = serde_json::from_value(json!({
-            "from": s("from"), "to": s("to"), "value": s("value"), "data": s("data"), "batch": s("batch"),
-            "nonce": s("nonce"), "validUntil": s("valid_until"), "mode": s("mode").parse::<u32>().unwrap(),
-            "relayer": s("relayer"), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}))
-        .unwrap();
-        let m = wire.to_sol().unwrap();
+        let wire = json!({"from": s("from"), "to": s("to"), "value": s("value"), "entryRef": s("entry_ref"),
+            "batch": s("batch"), "nonce": s("nonce"), "validUntil": s("valid_until"), "mode": s("mode").parse::<u32>().unwrap(),
+            "relayer": s("relayer"), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)});
+        let m = Mtx::from_wire(Some("transfer"), &wire).unwrap();
         let d = Domain {
             name: "SCaaS MetaToken".into(),
             version: "1".into(),
-            chain_id: k["chain_id"].as_u64().unwrap(),
+            chain_id: s("chain_id").parse().unwrap(),
             verifying_contract: s("verifying_contract").parse().unwrap(),
+            salt: s("salt").parse().unwrap(),
         };
-        let dg = digest(&d, &m);
+        let dg = m.digest(&d);
         assert_eq!(dg, s("digest").parse::<B256>().unwrap());
         let pk: [u8; 32] = alloy::hex::decode(&s("ed25519_public_key")[2..]).unwrap().try_into().unwrap();
         let sig: [u8; 64] = alloy::hex::decode(&s("ed25519_signature")[2..]).unwrap().try_into().unwrap();
         let vk = VerifyingKey::from_bytes(&pk).unwrap();
         vk.verify(dg.as_slice(), &Signature::from_bytes(&sig)).expect("ed25519 over the digest");
         // Hedera account 0.0.1234567 ⇒ long-zero `from`.
-        assert_eq!(m.from, Address::left_padding_from(&1_234_567u64.to_be_bytes()));
+        assert_eq!(m.from(), Address::left_padding_from(&1_234_567u64.to_be_bytes()));
     }
 
     /// Review H1/M1: a Hedera chain from `node.toml` (EVM-style: `evm_chain_number`, no `network`, finality
diff --git a/scaas-node/src/chain.rs b/scaas-node/src/chain.rs
index ea08f03..33912e7 100644
--- a/scaas-node/src/chain.rs
+++ b/scaas-node/src/chain.rs
@@ -11,7 +11,8 @@ use alloy::signers::local::PrivateKeySigner;
 use alloy::transports::TransportError;
 use anyhow::{anyhow, Result};
 
-use crate::abi::{decode_revert, IMetaToken, MetaTransaction};
+use crate::abi::{decode_revert, IToken};
+use crate::metatx::Mtx;
 use crate::config::ChainCfg;
 
 /// Simulation fail vì hợp đồng revert (vĩnh viễn với state này) hay vì đường truyền (tạm thời).
@@ -115,14 +116,17 @@ impl Chain {
         Ok(C::abi_decode_returns(&self.primary().call(tx).await?)?)
     }
 
-    /// `metaNonce(from, batch)` của token: nonce chủ thể kế tiếp (R80).
-    pub async fn meta_nonce(&self, token: Address, from: Address, batch: U256) -> Result<U256> {
-        self.view(token, IMetaToken::metaNonceCall { from, batch }).await
+    /// `mtxNonce(from, batch)`: the subject's next nonce on that lane, shared by both structs (R80, CTR-MTX-15).
+    pub async fn mtx_nonce(&self, token: Address, from: Address, batch: U256) -> Result<U256> {
+        self.view(token, IToken::mtxNonceCall { from, batch }).await
     }
 
-    /// `metaTxDigest(m)` — đúng digest token phát trong `MetaTransactionExecuted` (R78).
-    pub async fn meta_digest(&self, token: Address, m: MetaTransaction) -> Result<B256> {
-        self.view(token, IMetaToken::metaTxDigestCall { m }).await
+    /// `mtxDigest(m)` / `mtxTransferDigest(t)`: exactly the digest the contract emits in `MetaTransactionExecuted` (R78).
+    pub async fn mtx_digest(&self, token: Address, m: Mtx) -> Result<B256> {
+        match m {
+            Mtx::Call(m) => self.view(token, IToken::mtxDigestCall { m }).await,
+            Mtx::Transfer(t) => self.view(token, IToken::mtxTransferDigestCall { t }).await,
+        }
     }
 
     /// `MetaTransactionExecuted` của `(from, batch, nonce)` trong `lookback` khối gần nhất ⇒ `(digest, relayer)` (§8.5).
@@ -130,13 +134,13 @@ impl Chain {
         let latest = self.primary().get_block_number().await?;
         let filter = Filter::new()
             .address(token)
-            .event_signature(IMetaToken::MetaTransactionExecuted::SIGNATURE_HASH)
+            .event_signature(IToken::MetaTransactionExecuted::SIGNATURE_HASH)
             .topic1(from.into_word())
             .topic3(B256::from(batch))
             .from_block(latest.saturating_sub(lookback))
             .to_block(latest);
         for log in self.primary().get_logs(&filter).await? {
-            let Ok(e) = log.log_decode::<IMetaToken::MetaTransactionExecuted>().map(|l| l.inner.data) else { continue };
+            let Ok(e) = log.log_decode::<IToken::MetaTransactionExecuted>().map(|l| l.inner.data) else { continue };
             if e.nonce == nonce {
                 return Ok(Some((e.digest, e.relayer)));
             }
diff --git a/scaas-node/src/drift.rs b/scaas-node/src/drift.rs
index 3e1401b..aa9e4d7 100644
--- a/scaas-node/src/drift.rs
+++ b/scaas-node/src/drift.rs
@@ -12,7 +12,7 @@ use anyhow::Result;
 use serde_json::{json, Value};
 use tracing::info;
 
-use crate::abi::IMetaToken;
+use crate::abi::IToken;
 use crate::chain::Chain;
 use crate::indexer::receiving_pairs;
 use crate::odoo::Odoo;
@@ -38,9 +38,9 @@ pub async fn step(chain: &Chain, odoo: &Odoo, chain_key: &str) -> Result<bool> {
     for (token, who) in pairs {
         let tx = TransactionRequest::default()
             .with_to(token)
-            .with_input(IMetaToken::balanceOfCall { who }.abi_encode());
+            .with_input(IToken::balanceOfCall { who }.abi_encode());
         let out = chain.primary().call(tx).block(BlockId::number(height)).await?;
-        rows.push((token, who, IMetaToken::balanceOfCall::abi_decode_returns(&out)?));
+        rows.push((token, who, IToken::balanceOfCall::abi_decode_returns(&out)?));
     }
     let r = odoo.balance_report(chain_key, height, &report_rows(&rows)).await?;
     if !r.stale {
diff --git a/scaas-node/src/gateway.rs b/scaas-node/src/gateway.rs
index ba86d54..9322441 100644
--- a/scaas-node/src/gateway.rs
+++ b/scaas-node/src/gateway.rs
@@ -4,7 +4,6 @@ use std::collections::HashMap;
 use std::sync::{Arc, Mutex, RwLock};
 
 use alloy::primitives::{Address, Bytes, U256};
-use alloy::sol_types::SolCall;
 use axum::extract::{DefaultBodyLimit, Query, State};
 use axum::http::StatusCode;
 use axum::routing::{get, post};
@@ -14,12 +13,11 @@ use serde_json::{json, Value};
 use tokio::sync::mpsc;
 use tower::limit::GlobalConcurrencyLimitLayer;
 
-use crate::abi::IMetaToken;
 use crate::breaker::Breaker;
 use crate::chain::{Chain, SimError};
 use crate::dex::venue::{Venue, VenueError};
 use crate::dex::WireOrder;
-use crate::metatx::{normalize, WireMetaTx};
+use crate::metatx::Mtx;
 use crate::submit::{now, MetaRef, Work};
 
 #[derive(Clone)]
@@ -40,11 +38,14 @@ pub struct AppState {
     pub chains: Arc<HashMap<u64, GwChain>>,
 }
 
+/// `POST /v1/metatx {chain, token, struct?, m, signature}`: `struct` = `call` | `transfer` (default `transfer`).
 #[derive(Deserialize)]
 pub struct SignedReq {
     pub chain: u64,
     pub token: Address,
-    pub m: WireMetaTx,
+    #[serde(default, rename = "struct")]
+    pub struct_: Option<String>,
+    pub m: Value,
     pub signature: String,
 }
 
@@ -137,16 +138,15 @@ async fn enqueue(c: &GwChain, w: Work, status: &str) -> Reply {
 
 /// Nơi duy nhất dựng `Work` từ request; chuẩn hoá R84 ở đây, trước mô phỏng.
 fn work_of(r: SignedReq, fee_recipient: Option<Address>) -> Result<Work, Reply> {
-    let mut m = r.m.to_sol().map_err(bad)?;
-    normalize(&mut m, fee_recipient);
+    let mut m = Mtx::from_wire(r.struct_.as_deref(), &r.m).map_err(bad)?;
+    m.normalize(fee_recipient);
     let sig = sig_bytes(&r.signature)?;
-    if m.validUntil <= U256::from(now()) {
+    if m.valid_until() <= U256::from(now()) {
         return Err(bad("expired"));
     }
-    let valid_until = m.validUntil.saturating_to();
+    let valid_until = m.valid_until().saturating_to();
     let meta = Some(MetaRef::of(r.token, &m, None));
-    let data: Bytes = IMetaToken::executeMetaTransactionCall { m, signature: sig }.abi_encode().into();
-    Ok(Work { job_id: None, to: r.token, data, valid_until, meta })
+    Ok(Work { job_id: None, to: r.token, data: m.calldata(sig), valid_until, meta })
 }
 
 async fn post_metatx(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Reply {
@@ -162,13 +162,10 @@ async fn post_metatx(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Rep
         return sim_reply(e);
     }
     // G2: digest thật của token ⇒ cùng một intent gửi hai lần không thành hai tx vỏ (tập in-flight của chain).
-    let m = match IMetaToken::executeMetaTransactionCall::abi_decode(&w.data) {
-        Ok(c) => c.m,
-        Err(e) => return bad(e),
-    };
-    match c.chain.meta_digest(w.to, m).await {
+    let Some((m, _)) = Mtx::from_calldata(&w.data) else { return bad("not a meta-transaction") };
+    match c.chain.mtx_digest(w.to, m).await {
         Ok(d) => w.meta = w.meta.map(|r| MetaRef { digest: Some(d), ..r }),
-        Err(e) => return sim_reply(SimError::Transport(format!("metaTxDigest: {e:#}"))),
+        Err(e) => return sim_reply(SimError::Transport(format!("mtxDigest: {e:#}"))),
     }
     enqueue(c, w, "queued").await
 }
@@ -282,7 +279,8 @@ mod tests {
     use super::*;
     use axum::body::Body;
     use axum::http::Request;
-    use crate::metatx::MetaTransaction;
+    use crate::metatx::{Domain, MetaTransaction, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};
+    use alloy::primitives::B256;
     use tower::ServiceExt;
 
     /// R55 (review S1-7): lane đứng ⇒ gateway trả 503 ngay, không nhận rồi để hết hạn trong kênh.
@@ -304,9 +302,9 @@ mod tests {
         };
         let app = router(AppState { chains: Arc::new([(7, gw)].into_iter().collect()) });
         let body = json!({"chain": 7, "token": format!("{token:#x}"), "signature": "0x00", "m": {
-            "from": format!("{:#x}", Address::ZERO), "to": format!("{:#x}", Address::ZERO), "value": "1", "data": "0x",
-            "batch": "0", "nonce": "0", "validUntil": "99999999999", "mode": 0, "relayer": format!("{:#x}", Address::ZERO),
-            "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}});
+            "from": format!("{:#x}", Address::ZERO), "to": format!("{:#x}", Address::ZERO), "value": "1",
+            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "99999999999", "mode": 0,
+            "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}});
         let req = Request::builder().method("POST").uri("/v1/metatx").header("content-type", "application/json")
             .body(Body::from(body.to_string())).unwrap();
         let r = app.oneshot(req).await.unwrap();
@@ -315,46 +313,59 @@ mod tests {
         assert!(String::from_utf8_lossy(&b).contains("circuit breaker open: balance_floor"), "not the RPC error");
     }
 
+    /// A `call` request (`MetaTransaction`): `cancelNonce(1)` with a FIXED fee.
     fn req(mode: u32) -> SignedReq {
-        let m = WireMetaTx {
-            from: format!("{:#x}", Address::repeat_byte(0xab)),
-            to: format!("{:#x}", Address::repeat_byte(0x01)),
-            value: "1000000".into(),
-            data: "0x".into(),
-            batch: "7".into(),
-            nonce: "0".into(),
-            valid_until: "99999999999".into(),
+        let m = Mtx::Call(MetaTransaction {
+            from: Address::repeat_byte(0xab),
+            data: alloy::hex::decode("cfdd7aea0000000000000000000000000000000000000000000000000000000000000001").unwrap().into(),
+            batch: U256::from(7),
+            nonce: U256::ZERO,
+            validUntil: U256::from(99_999_999_999u64),
             mode,
-            relayer: format!("{:#x}", Address::repeat_byte(0x66)),
-            fee: "1000".into(),
-            fee_recipient: format!("{:#x}", Address::repeat_byte(0x77)),
-        };
-        SignedReq { chain: 7, token: Address::repeat_byte(0xcd), m, signature: format!("0x{}", "11".repeat(65)) }
+            relayer: Address::repeat_byte(0x66),
+            fee: U256::from(1000),
+            feeRecipient: Address::repeat_byte(0x77),
+        });
+        let (kind, wire) = m.to_wire();
+        SignedReq { chain: 7, token: Address::repeat_byte(0xcd), struct_: Some(kind.into()), m: wire,
+                    signature: format!("0x{}", "11".repeat(65)) }
+    }
+
+    fn sent(w: &Work) -> Mtx {
+        Mtx::from_calldata(&w.data).unwrap().0
     }
 
-    fn sent(w: &Work) -> MetaTransaction {
-        IMetaToken::executeMetaTransactionCall::abi_decode(&w.data).unwrap().m
+    fn wire(r: &SignedReq) -> Mtx {
+        Mtx::from_wire(r.struct_.as_deref(), &r.m).unwrap()
     }
 
     /// R84 (review C1): bit tắt ⇒ giá trị trên dây không được ký, ai cũng ghi đè được ⇒ không bao giờ gửi nó.
     #[test]
     fn unbound_fee_recipient_and_relayer_are_normalized() {
-        let d = crate::metatx::Domain { name: "T".into(), version: "1".into(), chain_id: 7, verifying_contract: Address::repeat_byte(0xcd) };
+        let d = Domain { name: "T".into(), version: "1".into(), chain_id: 7, verifying_contract: Address::repeat_byte(0xcd),
+                         salt: B256::repeat_byte(0x24) };
         let ours = Address::repeat_byte(0x99);
         let r = req(0x20);
-        let wire = r.m.to_sol().unwrap();
+        let signed = wire(&r);
         let m = sent(&work_of(r, Some(ours)).unwrap());
-        assert_eq!((m.feeRecipient, m.relayer), (ours, Address::ZERO));
-        assert_eq!(crate::metatx::digest(&d, &m), crate::metatx::digest(&d, &wire));
+        assert_eq!((m.fee_recipient(), m.relayer()), (ours, Address::ZERO));
+        assert_eq!(m.digest(&d), signed.digest(&d));
         let m = sent(&work_of(req(0x20), None).unwrap());
-        assert_eq!((m.feeRecipient, m.relayer), (Address::ZERO, Address::ZERO), "unset ⇒ the contract pays msg.sender");
+        assert_eq!((m.fee_recipient(), m.relayer()), (Address::ZERO, Address::ZERO), "unset ⇒ the contract pays msg.sender");
     }
 
     #[test]
     fn bound_fields_are_untouched() {
-        let mode = crate::metatx::MODE_RESTRICT_RELAYER | crate::metatx::MODE_RESTRICT_FEE_RECIPIENT | 0x20;
-        let r = req(mode);
-        let wire = r.m.to_sol().unwrap();
-        assert_eq!(sent(&work_of(r, Some(Address::repeat_byte(0x99))).unwrap()), wire);
+        let r = req(MODE_RESTRICT_RELAYER | MODE_RESTRICT_FEE_RECIPIENT | 0x20);
+        let signed = wire(&r);
+        assert_eq!(sent(&work_of(r, Some(Address::repeat_byte(0x99))).unwrap()), signed);
+    }
+
+    /// `struct` absent = `transfer`; a call body without `struct` is refused, never misread.
+    #[test]
+    fn the_struct_is_named_or_a_transfer() {
+        let mut r = req(0);
+        r.struct_ = None;
+        assert!(work_of(r, None).is_err());
     }
 }
diff --git a/scaas-node/src/indexer.rs b/scaas-node/src/indexer.rs
index 1a8d12c..b654d3d 100644
--- a/scaas-node/src/indexer.rs
+++ b/scaas-node/src/indexer.rs
@@ -9,7 +9,7 @@ use alloy::sol_types::SolEvent;
 use serde_json::{json, Value};
 use tracing::{info, warn};
 
-use crate::abi::IMetaToken;
+use crate::abi::IToken;
 use crate::chain::Chain;
 use crate::finality::{next_range, quorum_ok, safe_head, Mode};
 use crate::odoo::Odoo;
@@ -27,8 +27,8 @@ pub fn encode_event(log: &Log) -> Option<Value> {
         "log_index": log.log_index?,
     });
     let topic0 = *log.topic0()?;
-    if topic0 == IMetaToken::PaymentSettled::SIGNATURE_HASH {
-        let e = log.log_decode::<IMetaToken::PaymentSettled>().ok()?.inner.data;
+    if topic0 == IToken::PaymentSettled::SIGNATURE_HASH {
+        let e = log.log_decode::<IToken::PaymentSettled>().ok()?.inner.data;
         v["event"] = json!("PaymentSettled");
         v["from"] = json!(format!("{:#x}", e.from));
         v["to"] = json!(format!("{:#x}", e.to));
@@ -36,14 +36,14 @@ pub fn encode_event(log: &Log) -> Option<Value> {
         v["fee"] = json!(e.feeAmount.to_string());
         v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
         v["entry_ref"] = json!(format!("{:#x}", e.entryRef));
-    } else if topic0 == IMetaToken::Transfer::SIGNATURE_HASH {
-        let e = log.log_decode::<IMetaToken::Transfer>().ok()?.inner.data;
+    } else if topic0 == IToken::Transfer::SIGNATURE_HASH {
+        let e = log.log_decode::<IToken::Transfer>().ok()?.inner.data;
         v["event"] = json!("Transfer");
         v["from"] = json!(format!("{:#x}", e.from));
         v["to"] = json!(format!("{:#x}", e.to));
         v["amount"] = json!(e.value.to_string());
-    } else if topic0 == IMetaToken::MetaTransactionExecuted::SIGNATURE_HASH {
-        let e = log.log_decode::<IMetaToken::MetaTransactionExecuted>().ok()?.inner.data;
+    } else if topic0 == IToken::MetaTransactionExecuted::SIGNATURE_HASH {
+        let e = log.log_decode::<IToken::MetaTransactionExecuted>().ok()?.inner.data;
         v["event"] = json!("MetaTransactionExecuted");
         v["from"] = json!(format!("{:#x}", e.from));
         v["relayer"] = json!(format!("{:#x}", e.relayer));
@@ -125,8 +125,8 @@ pub async fn step(chain: &Chain, odoo: &Odoo) -> anyhow::Result<bool> {
         return Ok(false);
     }
     let f = Filter::new().from_block(from).to_block(to).address(addrs).event_signature(vec![
-        IMetaToken::PaymentSettled::SIGNATURE_HASH,
-        IMetaToken::MetaTransactionExecuted::SIGNATURE_HASH,
+        IToken::PaymentSettled::SIGNATURE_HASH,
+        IToken::MetaTransactionExecuted::SIGNATURE_HASH,
     ]);
     let mut events: Vec<Value> = chain.primary().get_logs(&f).await?.iter().filter_map(encode_event).collect();
     let pairs = receiving_pairs(&nc);
@@ -137,7 +137,7 @@ pub async fn step(chain: &Chain, odoo: &Odoo) -> anyhow::Result<bool> {
             .from_block(from)
             .to_block(to)
             .address(tokens)
-            .event_signature(IMetaToken::Transfer::SIGNATURE_HASH)
+            .event_signature(IToken::Transfer::SIGNATURE_HASH)
             .topic2(wallets);
         let logs = chain.primary().get_logs(&f).await?;
         events.extend(inbound(logs.iter().filter_map(encode_event).collect(), &pairs));
@@ -165,7 +165,7 @@ mod tests {
 
     #[test]
     fn payment_settled_is_encoded_for_odoo() {
-        let ev = IMetaToken::PaymentSettled {
+        let ev = IToken::PaymentSettled {
             from: Address::repeat_byte(1),
             to: Address::repeat_byte(2),
             amount: U256::from(250u64),
@@ -183,7 +183,7 @@ mod tests {
 
     #[test]
     fn executed_carries_the_digest() {
-        let ev = IMetaToken::MetaTransactionExecuted {
+        let ev = IToken::MetaTransactionExecuted {
             from: Address::repeat_byte(1),
             relayer: Address::repeat_byte(2),
             batch: U256::from(7u64),
@@ -202,7 +202,7 @@ mod tests {
     fn transfers_are_kept_only_to_the_receiving_wallet_of_that_token() {
         let (token, shop) = (Address::repeat_byte(9), Address::repeat_byte(0x5a));
         let ev = |to: Address| {
-            let t = IMetaToken::Transfer { from: Address::repeat_byte(7), to, value: U256::from(5u64) };
+            let t = IToken::Transfer { from: Address::repeat_byte(7), to, value: U256::from(5u64) };
             encode_event(&log_of(t.encode_log_data())).unwrap()
         };
         let v = ev(shop);
@@ -221,7 +221,7 @@ mod tests {
 
     #[test]
     fn pending_or_foreign_logs_are_dropped() {
-        let ev = IMetaToken::PaymentSettled {
+        let ev = IToken::PaymentSettled {
             from: Address::ZERO,
             to: Address::ZERO,
             amount: U256::ZERO,
diff --git a/scaas-node/src/mesh/accept.rs b/scaas-node/src/mesh/accept.rs
index 0874831..e26f6d6 100644
--- a/scaas-node/src/mesh/accept.rs
+++ b/scaas-node/src/mesh/accept.rs
@@ -36,6 +36,8 @@ pub struct ChainInfo {
     pub lanes: Vec<String>,
     /// `[[chains]] fee_recipient` (EVM/Hedera).
     pub fee_recipient: Option<String>,
+    /// EVM/Hedera: this chain's `chain_uid`, the salt of every SCaaS domain (NODE-GW-07); `None` ⇒ `UNKNOWN_CHAIN`.
+    pub chain_uid: Option<alloy::primitives::B256>,
     /// Aptos: package; Solana: program id — để kiểm dẫn xuất account (§4.4).
     pub program: Option<String>,
     /// TON: master (raw) → (hash, depth) của wallet code.
@@ -233,7 +235,7 @@ mod tests {
     }
 
     // --- một envelope EVM thật (ký bằng khoá secp256k1 + khoá hub) cho các mã không có trong vector §4.6.
-    use crate::metatx::{Domain, WireMetaTx};
+    use crate::metatx::{Domain, Mtx};
     use crate::signer::{Curve, LocalSigner, Signer};
     use ed25519_dalek::SigningKey;
     use serde_json::json;
@@ -241,15 +243,18 @@ mod tests {
 
     const TOKEN: &str = "0x00000000000000000000000000000000000070c0";
     const NOW: u64 = 1_800_000_000;
+    const UID: alloy::primitives::B256 = alloy::primitives::B256::repeat_byte(0x24);
 
     fn envelope(mode: u32, fee_recipient: &str, exclusive: Option<([u8; 32], u64)>) -> Vec<u8> {
         let user = LocalSigner::new(Curve::Secp256k1, &[9; 32]).unwrap();
         let z = format!("{:#x}", alloy::primitives::Address::ZERO);
-        let m = WireMetaTx { from: user.address_hex(), to: z.clone(), value: "1".into(), data: "0x".into(), batch: "1".into(),
-            nonce: "0".into(), valid_until: (NOW + 300).to_string(), mode, relayer: z, fee: "7".into(), fee_recipient: fee_recipient.into() };
-        let d = Domain { name: "T".into(), version: "1".into(), chain_id: 1, verifying_contract: TOKEN.parse().unwrap() };
-        let id = crate::metatx::digest(&d, &m.to_sol().unwrap()).0;
-        let body = json!({"domain": {"name": "T", "version": "1"}, "meta_tx": m, "signature": format!("0x{}", alloy::hex::encode(user.sign(&id).unwrap())), "sig_kind": "eoa"});
+        let m = json!({"from": user.address_hex(), "to": z, "value": "1", "entryRef": format!("{:#x}", alloy::primitives::B256::ZERO),
+            "batch": "1", "nonce": "0", "validUntil": (NOW + 300).to_string(), "mode": mode, "relayer": z, "fee": "7",
+            "feeRecipient": fee_recipient});
+        let d = Domain { name: "T".into(), version: "1".into(), chain_id: 1, verifying_contract: TOKEN.parse().unwrap(), salt: UID };
+        let id = Mtx::from_wire(Some("transfer"), &m).unwrap().digest(&d).0;
+        let body = json!({"domain": {"name": "T", "version": "1"}, "struct": "transfer", "meta_tx": m,
+            "signature": format!("0x{}", alloy::hex::encode(user.sign(&id).unwrap())), "sig_kind": "eoa"});
         let key = SigningKey::from_bytes(&[1; 32]);
         let hub = hubsig::peer_id(&key.verifying_key().to_bytes());
         let bh: [u8; 32] = Sha256::digest(envelope::canonical_body(&body).unwrap()).into();
@@ -273,7 +278,8 @@ mod tests {
 
     fn run(bytes: &[u8], source: Source, rows: &[PolicyRow], seen: bool, chain: &str) -> Result<Accepted, Code> {
         let info = ChainInfo { public: true, tokens: vec![TOKEN.into()], lanes: vec!["0xlane".into()],
-                               fee_recipient: Some("0x000000000000000000000000000000000000c01d".into()), ..Default::default() };
+                               fee_recipient: Some("0x000000000000000000000000000000000000c01d".into()), chain_uid: Some(UID),
+                               ..Default::default() };
         let chains = HashMap::from([(chain.to_string(), info)]);
         accept(bytes, source, &Ctx { now: NOW, params: MeshParams::default(), self_id: [5; 32], chains: &chains, policies: rows, seen: &Known(seen) })
     }
@@ -292,7 +298,8 @@ mod tests {
         assert_eq!((a.may_submit, a.state, a.hop_count), (true, State::Submittable, 1));
         assert_eq!(run(&open, peer, &rows, true, "evm:1").err(), Some(Code::Duplicate));
         assert_eq!(run(&open, peer, &[], false, "evm:2").err(), Some(Code::UnknownChain));
-        assert!(run(&open, peer, &rows, false, "evm:2").is_ok(), "a policy row makes the chain known (private by default)");
+        // a policy row makes a chain known, but an EVM intent needs the receiver's own chain_uid for its digest
+        assert_eq!(run(&open, peer, &rows, false, "evm:2").err(), Some(Code::UnknownChain));
         let none = vec![PolicyRow { support: Support::None, ..rows[0].clone() }];
         assert_eq!(run(&open, peer, &none, false, "evm:1").err(), Some(Code::Unsupported));
         // no matching row ⇒ forward_only, visibility from the chain profile
diff --git a/scaas-node/src/mesh/digest.rs b/scaas-node/src/mesh/digest.rs
index 850b32f..36065a5 100644
--- a/scaas-node/src/mesh/digest.rs
+++ b/scaas-node/src/mesh/digest.rs
@@ -10,14 +10,14 @@ use super::accept::ChainInfo;
 use super::envelope::Envelope;
 use super::Code;
 use crate::adapters::{aptos, solana, sui, ton};
-use crate::metatx::{self, Domain, MetaTransaction, WireMetaTx, MODE_FEE_MASK, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};
+use crate::metatx::{Domain, Mtx, MODE_FEE_MASK, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};
 
 const METAOP_DOMAIN: &str = "scaas.metaop.v1";
 
 /// Phần EVM mà L2 còn kiểm sau hạn (§7.2) và submitter dùng để dựng `Work`.
 #[derive(Debug, Clone)]
 pub struct Evm {
-    pub meta: MetaTransaction,
+    pub meta: Mtx,
     pub signature: Bytes,
     pub eoa: bool,
 }
@@ -49,10 +49,13 @@ struct EvmName {
     version: String,
 }
 
+/// `evm` body (mesh.md §3.3): `struct` = `call` | `transfer` (absent = `transfer`), `meta_tx` its wire form.
 #[derive(Deserialize)]
 struct EvmBody {
     domain: EvmName,
-    meta_tx: WireMetaTx,
+    #[serde(default, rename = "struct")]
+    struct_: Option<String>,
+    meta_tx: Value,
     signature: String,
     sig_kind: String,
 }
@@ -99,10 +102,12 @@ fn bytes0x(s: &str) -> Result<Vec<u8>, Code> {
 }
 
 /// `FeePolicy.compute` (NONE ⇒ 0, PERCENT ⇒ value × fee / 10^6, FIXED ⇒ fee); chặn trên khi tràn — mô phỏng phân xử.
-pub fn fee_effective(m: &MetaTransaction) -> U256 {
-    match (m.mode & MODE_FEE_MASK) >> 4 {
-        1 => m.value.saturating_mul(m.fee) / U256::from(1_000_000u64),
-        2 => m.fee,
+/// A PERCENT `MetaTransaction`'s basis is an argument of its selector (`mtxSelectors()`, NODE-JOB-20), which this pure
+/// layer does not read: it counts 0, so a `min_fee` floor never over-admits it.
+pub fn fee_effective(m: &Mtx) -> U256 {
+    match ((m.mode() & MODE_FEE_MASK) >> 4, m) {
+        (1, Mtx::Transfer(t)) => t.value.saturating_mul(t.fee) / U256::from(1_000_000u64),
+        (2, _) => m.fee(),
         _ => U256::ZERO,
     }
 }
@@ -129,7 +134,7 @@ fn nonzero(a: &[u8; 32], show: impl Fn(&[u8; 32]) -> String) -> Option<String> {
 /// `chain_key`/`contract` của envelope.
 pub fn decode(env: &Envelope, chain: &ChainInfo) -> Result<Decoded, Code> {
     match env.family.as_str() {
-        "evm" | "hedera" => evm(env),
+        "evm" | "hedera" => evm(env, chain),
         _ => {
             let body: OpBody = serde_json::from_value(env.body().clone()).map_err(|_| BAD)?;
             if body.op_kind != "pay" {
@@ -149,9 +154,11 @@ pub fn decode(env: &Envelope, chain: &ChainInfo) -> Result<Decoded, Code> {
     }
 }
 
-fn evm(env: &Envelope) -> Result<Decoded, Code> {
+fn evm(env: &Envelope, chain: &ChainInfo) -> Result<Decoded, Code> {
     let b: EvmBody = serde_json::from_value(env.body().clone()).map_err(|_| BAD)?;
-    let m = b.meta_tx.to_sol().map_err(|_| BAD)?; // MODE_KNOWN_MASK, nibble phí ≤ 2
+    let m = Mtx::from_wire(b.struct_.as_deref(), &b.meta_tx).map_err(|_| BAD)?; // MODE_KNOWN_MASK, nibble phí ≤ 2
+    // The salt is the receiver's own `chain_uid`, never a value from the envelope (NODE-MESH-08).
+    let salt = chain.chain_uid.ok_or(Code::UnknownChain)?;
     let contract: Address = env.contract.parse().map_err(|_| BAD)?;
     if format!("{contract:#x}") != env.contract {
         return Err(BAD);
@@ -166,18 +173,23 @@ fn evm(env: &Envelope) -> Result<Decoded, Code> {
         version: b.domain.version,
         chain_id: env.network().parse().map_err(|_| BAD)?,
         verifying_contract: contract,
+        salt,
+    };
+    let selector = match &m {
+        Mtx::Call(c) => hex0x(&c.data[..c.data.len().min(4)]),
+        Mtx::Transfer(t) if t.entryRef.is_zero() => "transfer".into(),
+        Mtx::Transfer(_) => "pay".into(),
     };
-    let data = &m.data;
     Ok(Decoded {
-        intent_id: metatx::digest(&domain, &m).0,
-        from: format!("{:#x}", m.from),
-        lane: m.batch.to_string(),
-        nonce: m.nonce.to_string(),
-        valid_until: u64::try_from(m.validUntil).unwrap_or(u64::MAX),
-        relayer: (m.mode & MODE_RESTRICT_RELAYER != 0).then(|| format!("{:#x}", m.relayer)),
-        fee_recipient: (m.mode & MODE_RESTRICT_FEE_RECIPIENT != 0).then(|| format!("{:#x}", m.feeRecipient)),
+        intent_id: m.digest(&domain).0,
+        from: format!("{:#x}", m.from()),
+        lane: m.batch().to_string(),
+        nonce: m.nonce().to_string(),
+        valid_until: u64::try_from(m.valid_until()).unwrap_or(u64::MAX),
+        relayer: (m.mode() & MODE_RESTRICT_RELAYER != 0).then(|| format!("{:#x}", m.relayer())),
+        fee_recipient: (m.mode() & MODE_RESTRICT_FEE_RECIPIENT != 0).then(|| format!("{:#x}", m.fee_recipient())),
         fee_effective: fee_effective(&m),
-        selector: hex0x(&data[..data.len().min(4)]),
+        selector,
         token: env.contract.clone(),
         account_ok: true,
         evm: Some(Evm { signature: bytes0x(&b.signature)?.into(), meta: m, eoa }),
@@ -187,7 +199,7 @@ fn evm(env: &Envelope) -> Result<Decoded, Code> {
 /// L2 EVM sau kiểm hạn (§4.4): relayer ràng buộc mà bằng 0 là intent chết; `eoa` ⇒ `ecrecover == from`, low-s,
 /// `v ∈ {27, 28}` như `ECDSA.tryRecover` của contract.
 pub fn check_evm(e: &Evm, intent_id: &[u8; 32]) -> Result<(), Code> {
-    if e.meta.mode & MODE_RESTRICT_RELAYER != 0 && e.meta.relayer == Address::ZERO {
+    if e.meta.mode() & MODE_RESTRICT_RELAYER != 0 && e.meta.relayer() == Address::ZERO {
         return Err(Code::RelayerBoundZero);
     }
     if !e.eoa {
@@ -197,7 +209,7 @@ pub fn check_evm(e: &Evm, intent_id: &[u8; 32]) -> Result<(), Code> {
     let ok = s.len() == 65
         && matches!(s[64], 27 | 28)
         && Signature::try_from(s.as_ref()).is_ok_and(|sig| {
-            sig.normalize_s().is_none() && sig.recover_address_from_prehash(&B256::from(*intent_id)).ok() == Some(e.meta.from)
+            sig.normalize_s().is_none() && sig.recover_address_from_prehash(&B256::from(*intent_id)).ok() == Some(e.meta.from())
         });
     ok.then_some(()).ok_or(Code::BadSignature)
 }
@@ -305,15 +317,18 @@ mod tests {
 
     #[test]
     fn effective_fee_per_mode() {
-        let mut m = WireMetaTx { from: format!("{:#x}", Address::ZERO), to: format!("{:#x}", Address::ZERO), value: "2000000".into(),
-            data: "0x".into(), batch: "0".into(), nonce: "0".into(), valid_until: "1".into(), mode: 0, relayer: format!("{:#x}", Address::ZERO),
-            fee: "1000000000000000000000000000000".into(), fee_recipient: format!("{:#x}", Address::ZERO) };
-        assert_eq!(fee_effective(&m.to_sol().unwrap()), U256::ZERO, "NONE ignores fee");
-        m.mode = 0x10;
-        m.fee = "2500".into();
-        assert_eq!(fee_effective(&m.to_sol().unwrap()), U256::from(5000u64), "PERCENT: 2e6 × 2500 / 1e6");
-        m.mode = 0x20;
-        assert_eq!(fee_effective(&m.to_sol().unwrap()), U256::from(2500u64));
+        let z = format!("{:#x}", Address::ZERO);
+        let w = |mode: u32| serde_json::json!({"from": z, "to": z, "value": "2000000",
+            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "1", "mode": mode,
+            "relayer": z, "fee": if mode == 0 { "1000000000000000000000000000000" } else { "2500" }, "feeRecipient": z});
+        let t = |mode| Mtx::from_wire(Some("transfer"), &w(mode)).unwrap();
+        assert_eq!(fee_effective(&t(0)), U256::ZERO, "NONE ignores fee");
+        assert_eq!(fee_effective(&t(0x10)), U256::from(5000u64), "PERCENT: 2e6 × 2500 / 1e6");
+        assert_eq!(fee_effective(&t(0x20)), U256::from(2500u64));
+        let call = |mode: u32| Mtx::from_wire(Some("call"), &serde_json::json!({"from": z, "data": "0x", "batch": "0",
+            "nonce": "0", "validUntil": "1", "mode": mode, "relayer": z, "fee": "2500", "feeRecipient": z})).unwrap();
+        assert_eq!(fee_effective(&call(0x10)), U256::ZERO, "a PERCENT call's basis is not read here");
+        assert_eq!(fee_effective(&call(0x20)), U256::from(2500u64));
     }
 
     proptest! {
diff --git a/scaas-node/src/metatx.rs b/scaas-node/src/metatx.rs
index e206373..ecf25bc 100644
--- a/scaas-node/src/metatx.rs
+++ b/scaas-node/src/metatx.rs
@@ -1,26 +1,46 @@
-//! Định dạng dây (chuỗi, như Odoo và gateway gửi) ↔ struct Solidity, và digest canonical.
-//! Quy tắc canonical-zeroing phải giống `MetaTxLib.canon` từng bit (spec §6).
+//! Wire format (strings, as clients and the gateway send them) ↔ the two signed structs, and their canonical digests
+//! (CTR-MTX-15): `MetaTransaction` (`struct = "call"`, an allowlisted self-call) and `MetaTransfer`
+//! (`struct = "transfer"`, a token transfer or payment), one lane space, in the salted domain
+//! `(name, version, chainId, contract, salt = chain_uid)`. Canonical zeroing is `MetaTxLib.canon` bit for bit.
 use std::str::FromStr;
 
 use alloy::primitives::{Address, Bytes, B256, U256};
-use alloy::sol_types::{Eip712Domain, SolStruct};
+use alloy::sol_types::{Eip712Domain, SolCall, SolStruct};
 use anyhow::{anyhow, bail, Result};
 use serde::{Deserialize, Serialize};
+use serde_json::Value;
 
-pub use crate::abi::MetaTransaction;
+pub use crate::abi::{MetaTransaction, MetaTransfer};
+use crate::abi::IToken;
 
 pub const MODE_RESTRICT_RELAYER: u32 = 0x01;
 pub const MODE_RESTRICT_FEE_RECIPIENT: u32 = 0x02;
 pub const MODE_FEE_MASK: u32 = 0xF0;
 pub const MODE_KNOWN_MASK: u32 = 0xF3;
 
+/// The 9 fields of `MetaTransaction` (camelCase, decimal strings).
 #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
-#[serde(rename_all = "camelCase")]
+#[serde(rename_all = "camelCase", deny_unknown_fields)]
 pub struct WireMetaTx {
+    pub from: String,
+    pub data: String,
+    pub batch: String,
+    pub nonce: String,
+    pub valid_until: String,
+    pub mode: u32,
+    pub relayer: String,
+    pub fee: String,
+    pub fee_recipient: String,
+}
+
+/// The 11 fields of `MetaTransfer`.
+#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
+#[serde(rename_all = "camelCase", deny_unknown_fields)]
+pub struct WireMetaTransfer {
     pub from: String,
     pub to: String,
     pub value: String,
-    pub data: String,
+    pub entry_ref: String,
     pub batch: String,
     pub nonce: String,
     pub valid_until: String,
@@ -30,12 +50,33 @@ pub struct WireMetaTx {
     pub fee_recipient: String,
 }
 
+/// EIP-712 domain of a SCaaS contract; `salt` is the chain's `chain_uid` (NET-ALL-22), never optional.
 #[derive(Debug, Clone)]
 pub struct Domain {
     pub name: String,
     pub version: String,
     pub chain_id: u64,
     pub verifying_contract: Address,
+    pub salt: B256,
+}
+
+impl Domain {
+    pub fn eip712(&self) -> Eip712Domain {
+        Eip712Domain::new(
+            Some(self.name.clone().into()),
+            Some(self.version.clone().into()),
+            Some(U256::from(self.chain_id)),
+            Some(self.verifying_contract),
+            Some(self.salt),
+        )
+    }
+}
+
+/// One signed meta-transaction, either struct.
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub enum Mtx {
+    Call(MetaTransaction),
+    Transfer(MetaTransfer),
 }
 
 pub(crate) fn addr(s: &str) -> Result<Address> {
@@ -56,17 +97,27 @@ pub(crate) fn uint(s: &str) -> Result<U256> {
     U256::from_str_radix(s, 10).map_err(|e| anyhow!("uint256 {s}: {e}"))
 }
 
+fn b32(s: &str) -> Result<B256> {
+    if s.len() != 66 || !s.starts_with("0x") {
+        bail!("not a bytes32: {s}");
+    }
+    B256::from_str(s).map_err(|e| anyhow!("bytes32 {s}: {e}"))
+}
+
+fn check_mode(mode: u32) -> Result<()> {
+    if mode & !MODE_KNOWN_MASK != 0 || (mode & MODE_FEE_MASK) >> 4 > 2 {
+        bail!("unknown mode bits {mode:#x}");
+    }
+    Ok(())
+}
+
 impl WireMetaTx {
     pub fn to_sol(&self) -> Result<MetaTransaction> {
         let hex = self.data.strip_prefix("0x").ok_or_else(|| anyhow!("data must be 0x-hex"))?;
         let data = alloy::hex::decode(hex).map_err(|e| anyhow!("data: {e}"))?;
-        if self.mode & !MODE_KNOWN_MASK != 0 || (self.mode & MODE_FEE_MASK) >> 4 > 2 {
-            bail!("unknown mode bits {:#x}", self.mode);
-        }
+        check_mode(self.mode)?;
         Ok(MetaTransaction {
             from: addr(&self.from)?,
-            to: addr(&self.to)?,
-            value: uint(&self.value)?,
             data: Bytes::from(data),
             batch: uint(&self.batch)?,
             nonce: uint(&self.nonce)?,
@@ -81,8 +132,6 @@ impl WireMetaTx {
     pub fn from_sol(m: &MetaTransaction) -> Self {
         Self {
             from: format!("{:#x}", m.from),
-            to: format!("{:#x}", m.to),
-            value: m.value.to_string(),
             data: format!("0x{}", alloy::hex::encode(&m.data)),
             batch: m.batch.to_string(),
             nonce: m.nonce.to_string(),
@@ -95,137 +144,313 @@ impl WireMetaTx {
     }
 }
 
-impl Domain {
-    pub fn eip712(&self) -> Eip712Domain {
-        Eip712Domain::new(
-            Some(self.name.clone().into()),
-            Some(self.version.clone().into()),
-            Some(U256::from(self.chain_id)),
-            Some(self.verifying_contract),
-            None,
-        )
+impl WireMetaTransfer {
+    pub fn to_sol(&self) -> Result<MetaTransfer> {
+        check_mode(self.mode)?;
+        Ok(MetaTransfer {
+            from: addr(&self.from)?,
+            to: addr(&self.to)?,
+            value: uint(&self.value)?,
+            entryRef: b32(&self.entry_ref)?,
+            batch: uint(&self.batch)?,
+            nonce: uint(&self.nonce)?,
+            validUntil: uint(&self.valid_until)?,
+            mode: self.mode,
+            relayer: addr(&self.relayer)?,
+            fee: uint(&self.fee)?,
+            feeRecipient: addr(&self.fee_recipient)?,
+        })
+    }
+
+    pub fn from_sol(t: &MetaTransfer) -> Self {
+        Self {
+            from: format!("{:#x}", t.from),
+            to: format!("{:#x}", t.to),
+            value: t.value.to_string(),
+            entry_ref: format!("{:#x}", t.entryRef),
+            batch: t.batch.to_string(),
+            nonce: t.nonce.to_string(),
+            valid_until: t.validUntil.to_string(),
+            mode: t.mode,
+            relayer: format!("{:#x}", t.relayer),
+            fee: t.fee.to_string(),
+            fee_recipient: format!("{:#x}", t.feeRecipient),
+        }
     }
 }
 
-/// Bản đã canonical-zero hoá: cái MetaTxLib thực sự băm.
-pub fn canonical(m: &MetaTransaction) -> MetaTransaction {
-    let mut c = m.clone();
-    if m.mode & MODE_RESTRICT_RELAYER == 0 {
-        c.relayer = Address::ZERO;
+impl Mtx {
+    /// `kind` = the job's or request's `struct`: `call` | `transfer`; absent = `transfer` (node/gateway.md). The wire
+    /// structs refuse unknown fields, so a body of the other struct never parses as this one.
+    pub fn from_wire(kind: Option<&str>, m: &Value) -> Result<Self> {
+        match kind.unwrap_or("transfer") {
+            "call" => Ok(Self::Call(serde_json::from_value::<WireMetaTx>(m.clone())?.to_sol()?)),
+            "transfer" => Ok(Self::Transfer(serde_json::from_value::<WireMetaTransfer>(m.clone())?.to_sol()?)),
+            k => bail!("unknown struct {k:?} (call | transfer)"),
+        }
     }
-    if m.mode & MODE_RESTRICT_FEE_RECIPIENT == 0 {
-        c.feeRecipient = Address::ZERO;
+
+    /// `(struct, wire)`, the inverse of `from_wire`.
+    pub fn to_wire(&self) -> (&'static str, Value) {
+        match self {
+            Self::Call(m) => ("call", serde_json::to_value(WireMetaTx::from_sol(m)).expect("plain struct")),
+            Self::Transfer(t) => ("transfer", serde_json::to_value(WireMetaTransfer::from_sol(t)).expect("plain struct")),
+        }
     }
-    c
-}
 
-/// R84: trường `canonical` xoá về 0 không được ký, ai cũng ghi đè được (`ERC20MetaTx` trả phí cho `feeRecipient`
-/// khác 0) ⇒ không bao giờ gửi giá trị trên dây. `fee_recipient` None ⇒ 0: contract trả cho `msg.sender`. Digest giữ nguyên.
-pub fn normalize(m: &mut MetaTransaction, fee_recipient: Option<Address>) {
-    if m.mode & MODE_RESTRICT_FEE_RECIPIENT == 0 {
-        m.feeRecipient = fee_recipient.unwrap_or(Address::ZERO);
+    pub fn from(&self) -> Address {
+        match self {
+            Self::Call(m) => m.from,
+            Self::Transfer(t) => t.from,
+        }
     }
-    if m.mode & MODE_RESTRICT_RELAYER == 0 {
-        m.relayer = Address::ZERO;
+
+    pub fn batch(&self) -> U256 {
+        match self {
+            Self::Call(m) => m.batch,
+            Self::Transfer(t) => t.batch,
+        }
+    }
+
+    pub fn nonce(&self) -> U256 {
+        match self {
+            Self::Call(m) => m.nonce,
+            Self::Transfer(t) => t.nonce,
+        }
+    }
+
+    pub fn valid_until(&self) -> U256 {
+        match self {
+            Self::Call(m) => m.validUntil,
+            Self::Transfer(t) => t.validUntil,
+        }
+    }
+
+    pub fn mode(&self) -> u32 {
+        match self {
+            Self::Call(m) => m.mode,
+            Self::Transfer(t) => t.mode,
+        }
+    }
+
+    pub fn relayer(&self) -> Address {
+        match self {
+            Self::Call(m) => m.relayer,
+            Self::Transfer(t) => t.relayer,
+        }
+    }
+
+    pub fn fee(&self) -> U256 {
+        match self {
+            Self::Call(m) => m.fee,
+            Self::Transfer(t) => t.fee,
+        }
+    }
+
+    pub fn fee_recipient(&self) -> Address {
+        match self {
+            Self::Call(m) => m.feeRecipient,
+            Self::Transfer(t) => t.feeRecipient,
+        }
     }
-}
 
-pub fn digest(domain: &Domain, m: &MetaTransaction) -> B256 {
-    canonical(m).eip712_signing_hash(&domain.eip712())
+    /// The selector a self-call runs (first 4 bytes of `data`); `None` for a `MetaTransfer`.
+    pub fn selector(&self) -> Option<[u8; 4]> {
+        match self {
+            Self::Call(m) => m.data.get(..4).map(|s| s.try_into().expect("4 bytes")),
+            Self::Transfer(_) => None,
+        }
+    }
+
+    /// What the contract hashes: the unbound `relayer` / `feeRecipient` as 0.
+    pub fn canonical(&self) -> Self {
+        let mut c = self.clone();
+        let mode = self.mode();
+        c.set_unbound(if mode & MODE_RESTRICT_RELAYER == 0 { Some(Address::ZERO) } else { None },
+            if mode & MODE_RESTRICT_FEE_RECIPIENT == 0 { Some(Address::ZERO) } else { None });
+        c
+    }
+
+    fn set_unbound(&mut self, relayer: Option<Address>, fee_recipient: Option<Address>) {
+        let (r, f) = match self {
+            Self::Call(m) => (&mut m.relayer, &mut m.feeRecipient),
+            Self::Transfer(t) => (&mut t.relayer, &mut t.feeRecipient),
+        };
+        if let Some(x) = relayer {
+            *r = x;
+        }
+        if let Some(x) = fee_recipient {
+            *f = x;
+        }
+    }
+
+    /// R84: a field the mode does not bind is not signed, anyone could overwrite it (the token pays the fee to a
+    /// non-zero `feeRecipient`) ⇒ never send the wire value. `fee_recipient` None ⇒ 0: the contract pays `msg.sender`.
+    /// The digest is unchanged.
+    pub fn normalize(&mut self, fee_recipient: Option<Address>) {
+        let mode = self.mode();
+        self.set_unbound(if mode & MODE_RESTRICT_RELAYER == 0 { Some(Address::ZERO) } else { None },
+            if mode & MODE_RESTRICT_FEE_RECIPIENT == 0 { Some(fee_recipient.unwrap_or(Address::ZERO)) } else { None });
+    }
+
+    pub fn digest(&self, domain: &Domain) -> B256 {
+        let d = domain.eip712();
+        match self.canonical() {
+            Self::Call(m) => m.eip712_signing_hash(&d),
+            Self::Transfer(t) => t.eip712_signing_hash(&d),
+        }
+    }
+
+    pub fn struct_hash(&self) -> B256 {
+        match self.canonical() {
+            Self::Call(m) => m.eip712_hash_struct(),
+            Self::Transfer(t) => t.eip712_hash_struct(),
+        }
+    }
+
+    /// The relayed calldata: `mtxExecute(m, sig)` or `mtxExecuteTransfer(t, sig)`.
+    pub fn calldata(&self, signature: Bytes) -> Bytes {
+        match self.clone() {
+            Self::Call(m) => IToken::mtxExecuteCall { m, signature }.abi_encode().into(),
+            Self::Transfer(t) => IToken::mtxExecuteTransferCall { t, signature }.abi_encode().into(),
+        }
+    }
+
+    /// Inverse of `calldata`: `(mtx, signature)`, `None` for any other call.
+    pub fn from_calldata(data: &[u8]) -> Option<(Self, Bytes)> {
+        if let Ok(c) = IToken::mtxExecuteCall::abi_decode(data) {
+            return Some((Self::Call(c.m), c.signature));
+        }
+        IToken::mtxExecuteTransferCall::abi_decode(data).ok().map(|c| (Self::Transfer(c.t), c.signature))
+    }
 }
 
 #[cfg(test)]
 mod tests {
     use super::*;
+    use serde_json::json;
 
-    fn kat() -> serde_json::Value {
-        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/metatx_v1_kat.json");
+    fn kat(name: &str) -> Value {
+        let p = format!("{}/../smartcontracts/evm/test/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
         serde_json::from_str(&std::fs::read_to_string(p).expect("KAT file")).expect("KAT json")
     }
 
-    fn sample() -> WireMetaTx {
-        WireMetaTx {
-            from: format!("{:#x}", Address::repeat_byte(0xab)),
-            to: format!("{:#x}", Address::repeat_byte(0x01)),
-            value: "100".into(),
-            data: "0x".into(),
-            batch: "7".into(),
-            nonce: "0".into(),
-            valid_until: "1800000300".into(),
-            mode: MODE_RESTRICT_RELAYER,
-            relayer: format!("{:#x}", Address::repeat_byte(0x02)),
-            fee: "0".into(),
-            fee_recipient: format!("{:#x}", Address::ZERO),
+    fn domain_of(k: &Value) -> Domain {
+        let s = |f: &str| k[f].as_str().expect(f).to_string();
+        Domain {
+            name: s("domain_name"),
+            version: s("domain_version"),
+            chain_id: s("chain_id").parse().unwrap(),
+            verifying_contract: s("verifying_contract").parse().unwrap(),
+            salt: s("salt").parse().unwrap(),
         }
     }
 
-    fn sample_domain() -> Domain {
-        Domain {
-            name: "SCaaS MetaToken".into(),
-            version: "1".into(),
-            chain_id: 7622,
-            verifying_contract: Address::repeat_byte(0xcd),
-        }
+    fn sig_of(k: &Value) -> Bytes {
+        alloy::hex::decode(&k["signature"].as_str().unwrap()[2..]).unwrap().into()
     }
 
+    /// Byte-identical with forge (`TokenKat.t.sol`): struct hash, digest and the relayed `mtxExecute` calldata.
     #[test]
-    fn digest_matches_forge_kat() {
-        let k = kat();
+    fn call_digest_and_calldata_match_forge_kat() {
+        let k = kat("metatx_kat.json");
         let s = |f: &str| k[f].as_str().expect(f).to_string();
-        let wire = WireMetaTx {
-            from: s("from"),
-            to: s("to"),
-            value: s("value"),
-            data: s("data"),
-            batch: s("batch"),
-            nonce: s("nonce"),
-            valid_until: s("valid_until"),
-            mode: s("mode").parse().unwrap(),
-            relayer: s("relayer"),
-            fee: s("fee"),
-            fee_recipient: s("fee_recipient"),
-        };
-        let domain = Domain {
-            name: s("domain_name"),
-            version: s("domain_version"),
-            chain_id: s("chain_id").parse().unwrap(),
-            verifying_contract: Address::from_str(&s("verifying_contract")).unwrap(),
-        };
-        let m = wire.to_sol().unwrap();
-        assert_eq!(format!("{:#x}", canonical(&m).eip712_hash_struct()), s("struct_hash").to_lowercase());
-        assert_eq!(format!("{:#x}", digest(&domain, &m)), s("digest").to_lowercase());
+        let wire = json!({"from": s("from"), "data": s("data"), "batch": s("batch"), "nonce": s("nonce"),
+            "validUntil": s("valid_until"), "mode": s("mode").parse::<u32>().unwrap(), "relayer": s("relayer"),
+            "fee": s("fee"), "feeRecipient": s("fee_recipient")});
+        let m = Mtx::from_wire(Some("call"), &wire).unwrap();
+        assert_eq!(format!("{:#x}", m.struct_hash()), s("struct_hash").to_lowercase());
+        assert_eq!(format!("{:#x}", m.digest(&domain_of(&k))), s("digest").to_lowercase());
+        assert_eq!(format!("0x{}", alloy::hex::encode(m.calldata(sig_of(&k)))), s("calldata").to_lowercase());
+        assert_eq!(Mtx::from_calldata(&m.calldata(sig_of(&k))), Some((m.clone(), sig_of(&k))));
+        assert_eq!(m.selector(), Some([0xcf, 0xdd, 0x7a, 0xea]), "cancelNonce(uint256)");
+    }
+
+    #[test]
+    fn transfer_digest_and_calldata_match_forge_kat() {
+        let k = kat("metatransfer_kat.json");
+        let s = |f: &str| k[f].as_str().expect(f).to_string();
+        let wire = json!({"from": s("from"), "to": s("to"), "value": s("value"), "entryRef": s("entry_ref"),
+            "batch": s("batch"), "nonce": s("nonce"), "validUntil": s("valid_until"),
+            "mode": s("mode").parse::<u32>().unwrap(), "relayer": s("relayer"), "fee": s("fee"),
+            "feeRecipient": s("fee_recipient")});
+        let t = Mtx::from_wire(None, &wire).unwrap();
+        assert!(matches!(t, Mtx::Transfer(_)), "absent struct = transfer");
+        assert_eq!(format!("{:#x}", t.struct_hash()), s("struct_hash").to_lowercase());
+        assert_eq!(format!("{:#x}", t.digest(&domain_of(&k))), s("digest").to_lowercase());
+        assert_eq!(format!("0x{}", alloy::hex::encode(t.calldata(sig_of(&k)))), s("calldata").to_lowercase());
+        assert_eq!(t.selector(), None);
+    }
+
+    fn call() -> Mtx {
+        Mtx::Call(MetaTransaction {
+            from: Address::repeat_byte(0xab),
+            data: Bytes::from_static(&[1, 2, 3, 4]),
+            batch: U256::from(7),
+            nonce: U256::ZERO,
+            validUntil: U256::from(1_800_000_300u64),
+            mode: MODE_RESTRICT_RELAYER,
+            relayer: Address::repeat_byte(0x02),
+            fee: U256::ZERO,
+            feeRecipient: Address::ZERO,
+        })
+    }
+
+    fn domain() -> Domain {
+        Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: 7622,
+                 verifying_contract: Address::repeat_byte(0xcd), salt: B256::repeat_byte(0x24) }
     }
 
     #[test]
-    fn unflagged_fee_recipient_does_not_change_the_digest() {
-        let mut m = sample().to_sol().unwrap();
-        let d = sample_domain();
-        let a = digest(&d, &m);
+    fn unflagged_fields_do_not_change_the_digest_and_the_salt_does() {
+        let d = domain();
+        let a = call().digest(&d);
+        let Mtx::Call(mut m) = call() else { unreachable!() };
         m.feeRecipient = Address::repeat_byte(0x11);
-        assert_eq!(a, digest(&d, &m));
+        assert_eq!(a, Mtx::Call(m.clone()).digest(&d));
         m.mode |= MODE_RESTRICT_FEE_RECIPIENT;
-        assert_ne!(a, digest(&d, &m));
+        assert_ne!(a, Mtx::Call(m).digest(&d));
+        assert_ne!(a, call().digest(&Domain { salt: B256::repeat_byte(0x25), ..d }), "chain_uid is signed");
     }
 
     #[test]
-    fn wire_rejects_garbage() {
-        let mut w = sample();
-        w.value = "01".into();
-        assert!(w.to_sol().is_err());
-        let mut w = sample();
-        w.from = "0x12".into();
-        assert!(w.to_sol().is_err());
-        let mut w = sample();
-        w.mode = 0x04;
-        assert!(w.to_sol().is_err());
-        let mut w = sample();
-        w.data = "zz".into();
-        assert!(w.to_sol().is_err());
+    fn normalize_zeroes_unbound_fields_and_keeps_the_digest() {
+        let d = domain();
+        let Mtx::Call(mut m) = call() else { unreachable!() };
+        m.mode = 0x20;
+        m.relayer = Address::repeat_byte(0x66);
+        m.feeRecipient = Address::repeat_byte(0x77);
+        let wire = Mtx::Call(m.clone());
+        let mut x = wire.clone();
+        x.normalize(Some(Address::repeat_byte(0x99)));
+        assert_eq!((x.relayer(), x.fee_recipient()), (Address::ZERO, Address::repeat_byte(0x99)));
+        assert_eq!(x.digest(&d), wire.digest(&d));
+        let mut bound = Mtx::Call(MetaTransaction { mode: 0x23, ..m });
+        let before = bound.clone();
+        bound.normalize(Some(Address::repeat_byte(0x99)));
+        assert_eq!(bound, before, "bound fields are untouched");
+    }
+
+    #[test]
+    fn wire_rejects_garbage_and_the_other_struct() {
+        let (_, good) = call().to_wire();
+        let bad = |f: &str, v: Value| {
+            let mut w = good.clone();
+            w[f] = v;
+            Mtx::from_wire(Some("call"), &w).is_err()
+        };
+        assert!(bad("batch", json!("01")));
+        assert!(bad("from", json!("0x12")));
+        assert!(bad("mode", json!(4)));
+        assert!(bad("data", json!("zz")));
+        assert!(bad("value", json!("1")), "a transfer field in a call");
+        assert!(Mtx::from_wire(None, &good).is_err(), "a call body is not a transfer");
+        assert!(Mtx::from_wire(Some("ua"), &good).is_err());
     }
 
     #[test]
     fn wire_round_trips() {
-        let m = sample().to_sol().unwrap();
-        assert_eq!(WireMetaTx::from_sol(&m).to_sol().unwrap(), m);
+        let (kind, w) = call().to_wire();
+        assert_eq!(Mtx::from_wire(Some(kind), &w).unwrap(), call());
     }
 }
diff --git a/scaas-node/src/odoo.rs b/scaas-node/src/odoo.rs
index 10c8d40..2941997 100644
--- a/scaas-node/src/odoo.rs
+++ b/scaas-node/src/odoo.rs
@@ -6,7 +6,6 @@ use serde::{Deserialize, Serialize};
 use serde_json::{json, Value};
 
 use crate::config::OdooCfg;
-use crate::metatx::WireMetaTx;
 
 #[derive(Clone)]
 pub struct Odoo {
@@ -73,7 +72,8 @@ impl NodeConfig {
     }
 }
 
-/// Một job outbox. `kind = "metatx"`: `token`/`signature`/`metatx` có mặt. `kind = "call"`:
+/// Một job outbox. `kind = "metatx"`: `token`/`signature`/`metatx` có mặt, `struct` names the signed struct
+/// (`call` = `MetaTransaction`, `transfer` = `MetaTransfer`; absent = `transfer`, CTR-MTX-15). `kind = "call"`:
 /// chỉ `call` — calldata Odoo đã dựng (MandateWallet, R25), node chỉ gửi.
 #[derive(Debug, Clone, Deserialize)]
 pub struct Job {
@@ -84,8 +84,10 @@ pub struct Job {
     pub digest: Option<String>,
     #[serde(default)]
     pub signature: Option<String>,
+    #[serde(default, rename = "struct")]
+    pub struct_: Option<String>,
     #[serde(default)]
-    pub metatx: Option<WireMetaTx>,
+    pub metatx: Option<Value>,
     #[serde(default)]
     pub call: Option<WireCall>,
     /// `metatx` | `call` | `signed_op` (họ không phải EVM: payload ký + chữ ký + khoá công khai, adapter tự đọc).
@@ -227,15 +229,17 @@ mod tests {
     #[test]
     fn job_payload_from_odoo_decodes() {
         let raw = r#"{"id": 3, "token": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
-            "digest": "0x33", "signature": "0x44",
+            "digest": "0x33", "signature": "0x44", "struct": "transfer",
             "metatx": {"from": "0xabababababababababababababababababababab",
                        "to": "0x0101010101010101010101010101010101010101", "value": "100",
-                       "data": "0x", "batch": "7", "nonce": "0", "validUntil": "1800000300",
+                       "entryRef": "0x0000000000000000000000000000000000000000000000000000000000000042",
+                       "batch": "7", "nonce": "0", "validUntil": "1800000300",
                        "mode": 1, "relayer": "0x0202020202020202020202020202020202020202",
                        "fee": "0", "feeRecipient": "0x0000000000000000000000000000000000000000"}}"#;
         let job: Job = serde_json::from_str(raw).unwrap();
         assert_eq!(job.id, 3);
-        assert_eq!(job.metatx.unwrap().to_sol().unwrap().batch, alloy::primitives::U256::from(7));
+        let m = crate::metatx::Mtx::from_wire(job.struct_.as_deref(), job.metatx.as_ref().unwrap()).unwrap();
+        assert_eq!(m.batch(), alloy::primitives::U256::from(7));
     }
 
     #[test]
diff --git a/scaas-node/src/submit.rs b/scaas-node/src/submit.rs
index 9ce5ff9..ddaba11 100644
--- a/scaas-node/src/submit.rs
+++ b/scaas-node/src/submit.rs
@@ -11,15 +11,14 @@ use std::time::{Duration, Instant};
 use alloy::primitives::{Address, Bytes, B256, U256};
 use alloy::providers::Provider;
 use alloy::rpc::types::TransactionReceipt;
-use alloy::sol_types::SolCall;
 use anyhow::Result;
 use tokio::sync::mpsc;
 use tracing::{info, warn};
 
-use crate::abi::{IMetaToken, MetaTransaction};
 use crate::breaker::Breaker;
 use crate::chain::{Chain, SimError};
 use crate::config::ChainCfg;
+use crate::metatx::Mtx;
 use crate::nonce::{bump, plan, Inflight};
 use crate::odoo::{Job, Odoo, Report};
 
@@ -56,8 +55,8 @@ pub struct MetaRef {
 }
 
 impl MetaRef {
-    pub fn of(token: Address, m: &MetaTransaction, digest: Option<B256>) -> Self {
-        Self { token, from: m.from, batch: m.batch, nonce: m.nonce, digest }
+    pub fn of(token: Address, m: &Mtx, digest: Option<B256>) -> Self {
+        Self { token, from: m.from(), batch: m.batch(), nonce: m.nonce(), digest }
     }
 }
 
@@ -114,12 +113,11 @@ pub fn work_from_job(job: &Job) -> Result<Work> {
     let (Some(m), Some(token), Some(sig)) = (&job.metatx, job.token, &job.signature) else {
         anyhow::bail!("job {} has neither a meta-transaction nor a call", job.id);
     };
-    let m = m.to_sol()?;
+    let m = Mtx::from_wire(job.struct_.as_deref(), m)?;
     let sig = alloy::hex::decode(sig.strip_prefix("0x").unwrap_or(sig))?;
-    let valid_until = m.validUntil.saturating_to();
+    let valid_until = m.valid_until().saturating_to();
     let meta = Some(MetaRef::of(token, &m, job_digest(job)));
-    let data = IMetaToken::executeMetaTransactionCall { m, signature: sig.into() }.abi_encode();
-    Ok(Work { job_id: Some(job.id), to: token, data: data.into(), valid_until, meta })
+    Ok(Work { job_id: Some(job.id), to: token, data: m.calldata(sig.into()), valid_until, meta })
 }
 
 pub fn now() -> u64 {
@@ -333,15 +331,15 @@ impl Submitter {
         match self.consumed(w).await {
             Ok(true) => self.report_consumed(w).await,
             Ok(false) => self.fail(w, reason).await,
-            Err(e) => self.requeue(w, format!("metaNonce: {e:#}")).await,
+            Err(e) => self.requeue(w, format!("mtxNonce: {e:#}")).await,
         }
     }
 
-    /// R80: `metaNonce(from, batch) > nonce` ⇔ nonce chủ thể của meta-tx đã bị dùng (bởi ai thì `classify`).
+    /// R80: `mtxNonce(from, batch) > nonce` ⇔ nonce chủ thể của meta-tx đã bị dùng (bởi ai thì `classify`).
     /// `Ok(false)` cho job `call`. Lỗi RPC ⇒ `Err`: người gọi không bump, không kết luận (fail closed).
     async fn consumed(&self, w: &Work) -> Result<bool> {
         let Some(m) = &w.meta else { return Ok(false) };
-        Ok(self.chain.meta_nonce(m.token, m.from, m.batch).await? > m.nonce)
+        Ok(self.chain.mtx_nonce(m.token, m.from, m.batch).await? > m.nonce)
     }
 
     /// §8.5 — chỉ là nhãn cho `last_error` ở Odoo; `landed_elsewhere` do indexer quyết khi `final`.
@@ -431,7 +429,7 @@ impl Submitter {
             if let Some(w) = s.work.clone().filter(|w| w.meta.is_some()) {
                 match self.consumed(&w).await {
                     Err(e) => {
-                        warn!(nonce = n, "metaNonce: {e:#}; no bump this round");
+                        warn!(nonce = n, "mtxNonce: {e:#}; no bump this round");
                         continue;
                     }
                     Ok(true) => {
@@ -517,7 +515,7 @@ impl Submitter {
             Some(w) if !rc.status() => match self.consumed(w).await {
                 Ok(c) => c,
                 Err(e) => {
-                    warn!(nonce = n, "reverted receipt, metaNonce unreadable; retry: {e:#}");
+                    warn!(nonce = n, "reverted receipt, mtxNonce unreadable; retry: {e:#}");
                     return;
                 }
             },
@@ -595,12 +593,12 @@ mod tests {
     use alloy::consensus::{Transaction as _, TxEnvelope};
     use alloy::eips::eip2718::Decodable2718;
     use alloy::signers::local::PrivateKeySigner;
-    use alloy::sol_types::SolValue;
+    use alloy::sol_types::{SolCall, SolValue};
     use serde_json::{json, Value};
 
     use super::*;
+    use crate::abi::{IToken, MetaTransfer};
     use crate::adapter::tests::{fake_odoo, Fake, Shared};
-    use crate::metatx::WireMetaTx;
 
     const D: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";
     const TOKEN: Address = Address::repeat_byte(0xcd);
@@ -608,10 +606,10 @@ mod tests {
     /// Chain EVM giả qua JSON-RPC thật (alloy nói chuyện với nó như với node thật).
     #[derive(Default)]
     struct Evm {
-        /// Mô phỏng `executeMetaTransaction`: `None` ok, `"revert"`, `"transport"`.
+        /// Mô phỏng `mtxExecuteTransfer`: `None` ok, `"revert"`, `"transport"`.
         sim: Option<&'static str>,
-        /// `metaNonce`: `None` ⇒ lỗi RPC.
-        meta_nonce: Option<u64>,
+        /// `mtxNonce`: `None` ⇒ lỗi RPC.
+        mtx_nonce: Option<u64>,
         /// Số tx của lane đã vào khối (`latest` = `pending`).
         count: u64,
         receipts: HashMap<B256, bool>,
@@ -641,12 +639,12 @@ mod tests {
                 "eth_call" => {
                     let input = p[0]["input"].as_str().or(p[0]["data"].as_str()).unwrap();
                     let sel = alloy::hex::decode(&input[2..10]).unwrap();
-                    if sel == IMetaToken::metaNonceCall::SELECTOR {
-                        e.meta_nonce.map(|n| word(U256::from(n))).ok_or_else(|| err(-32000, "upstream timeout", None))
+                    if sel == IToken::mtxNonceCall::SELECTOR {
+                        e.mtx_nonce.map(|n| word(U256::from(n))).ok_or_else(|| err(-32000, "upstream timeout", None))
                     } else {
                         match e.sim {
                             Some("revert") => {
-                                let data = IMetaToken::MetaTxBadNonce { expected: U256::from(1), got: U256::ZERO };
+                                let data = IToken::MetaTxBadNonce { expected: U256::from(1), got: U256::ZERO };
                                 let data = alloy::sol_types::SolError::abi_encode(&data);
                                 Err(err(3, "execution reverted", Some(format!("0x{}", alloy::hex::encode(data)))))
                             }
@@ -689,12 +687,12 @@ mod tests {
         (url, s)
     }
 
-    fn meta(batch: u64) -> MetaTransaction {
-        MetaTransaction {
+    fn meta(batch: u64) -> Mtx {
+        Mtx::Transfer(MetaTransfer {
             from: Address::repeat_byte(0xab),
             to: Address::repeat_byte(0x5e),
             value: U256::from(1_000u64),
-            data: Default::default(),
+            entryRef: B256::repeat_byte(0x42),
             batch: U256::from(batch),
             nonce: U256::ZERO,
             validUntil: U256::from(now() + 600),
@@ -702,12 +700,13 @@ mod tests {
             relayer: Address::ZERO,
             fee: U256::ZERO,
             feeRecipient: Address::ZERO,
-        }
+        })
     }
 
     fn job(id: i64) -> Value {
-        json!({"id": id, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": D,
-               "signature": format!("0x{}", "11".repeat(65)), "metatx": WireMetaTx::from_sol(&meta(7))})
+        let (kind, wire) = meta(7).to_wire();
+        json!({"id": id, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
+               "signature": format!("0x{}", "11".repeat(65)), "metatx": wire})
     }
 
     async fn lane(rpc: &str, odoo: crate::odoo::Odoo, key: u8, set: InflightSet) -> Submitter {
@@ -742,8 +741,8 @@ mod tests {
     /// R80: kẹt mà nonce chủ thể đã bị dùng ⇒ `consumed`, nonce vỏ lấp bằng gap-filler, meta-tx KHÔNG bao giờ gửi lại.
     #[tokio::test]
     async fn consumed_before_bump_gap_fills_and_never_resends_the_metatx() {
-        let (mut s, rpc, o, set) = sent_one(Evm { meta_nonce: Some(0), ..Default::default() }).await;
-        rpc.lock().unwrap().meta_nonce = Some(1);
+        let (mut s, rpc, o, set) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
+        rpc.lock().unwrap().mtx_nonce = Some(1);
         let before = BUMP_SKIPPED_CONSUMED.load(Ordering::Relaxed);
         s.track().await;
         s.track().await;
@@ -760,11 +759,11 @@ mod tests {
         assert!(!set.contains(&D.parse().unwrap()));
     }
 
-    /// R80 fail closed: `metaNonce` không đọc được ⇒ không bump vòng này.
+    /// R80 fail closed: `mtxNonce` không đọc được ⇒ không bump vòng này.
     #[tokio::test]
-    async fn unreadable_meta_nonce_means_no_bump() {
-        let (mut s, rpc, o, _) = sent_one(Evm { meta_nonce: Some(0), ..Default::default() }).await;
-        rpc.lock().unwrap().meta_nonce = None;
+    async fn unreadable_mtx_nonce_means_no_bump() {
+        let (mut s, rpc, o, _) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
+        rpc.lock().unwrap().mtx_nonce = None;
         s.track().await;
         assert_eq!(rpc.lock().unwrap().sent.len(), 1);
         assert_eq!(states(&o), ["signed", "broadcast"]);
@@ -773,7 +772,7 @@ mod tests {
     /// `Sent.hashes`: bản đã bị thay thế mà vào khối vẫn được nhận ra (trước đây bị thử lại mãi).
     #[tokio::test]
     async fn an_earlier_replaced_hash_that_mines_settles_the_nonce() {
-        let (mut s, rpc, o, _) = sent_one(Evm { meta_nonce: Some(0), ..Default::default() }).await;
+        let (mut s, rpc, o, _) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
         s.track().await;
         let sent = rpc.lock().unwrap().sent.clone();
         assert_eq!((sent.len(), &sent[1].2), (2, &sent[0].2), "live and unconsumed ⇒ the meta-tx is bumped");
@@ -787,16 +786,16 @@ mod tests {
     /// Review H3: tx của ta revert vì người khác đã dùng nonce ⇒ `consumed`, không `reverted`. Đọc nonce hỏng ⇒ giữ, thử lại.
     #[tokio::test]
     async fn a_reverted_receipt_of_a_consumed_metatx_reports_consumed() {
-        let (mut s, rpc, o, _) = sent_one(Evm { meta_nonce: Some(0), ..Default::default() }).await;
+        let (mut s, rpc, o, _) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
         let h = rpc.lock().unwrap().sent[0].0;
         rpc.lock().unwrap().receipts.insert(h, false);
-        rpc.lock().unwrap().meta_nonce = None;
+        rpc.lock().unwrap().mtx_nonce = None;
         s.track().await;
         assert_eq!((s.inflight_count(), states(&o).len()), (1, 2), "unreadable ⇒ kept, nothing reported");
-        rpc.lock().unwrap().meta_nonce = Some(1);
+        rpc.lock().unwrap().mtx_nonce = Some(1);
         s.track().await;
         assert_eq!(states(&o), ["signed", "broadcast", "consumed"]);
-        let (mut s, rpc, o, _) = sent_one(Evm { meta_nonce: Some(0), ..Default::default() }).await;
+        let (mut s, rpc, o, _) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
         let h = rpc.lock().unwrap().sent[0].0;
         rpc.lock().unwrap().receipts.insert(h, false);
         s.track().await;
@@ -807,10 +806,10 @@ mod tests {
     #[tokio::test]
     async fn simulation_revert_is_classified_by_the_subject_nonce() {
         for (nonce, want) in [(Some(1), "consumed"), (Some(0), "dead"), (None, "queued")] {
-            let (url, _) = fake_evm(Evm { sim: Some("revert"), meta_nonce: nonce, ..Default::default() }).await;
+            let (url, _) = fake_evm(Evm { sim: Some("revert"), mtx_nonce: nonce, ..Default::default() }).await;
             let (odoo, o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: json!([]), ..Default::default() }).await;
             lane(&url, odoo, 1, InflightSet::default()).await.poll_outbox().await;
-            assert_eq!(states(&o), [want], "metaNonce {nonce:?}");
+            assert_eq!(states(&o), [want], "mtxNonce {nonce:?}");
         }
     }
 
@@ -818,7 +817,7 @@ mod tests {
     /// Lỗi tạm thời nhả digest ngay (không ai bị chặn tới hết hạn).
     #[tokio::test]
     async fn one_digest_is_signed_once_across_lanes_and_released_on_transient_errors() {
-        let (url, rpc) = fake_evm(Evm { meta_nonce: Some(0), ..Default::default() }).await;
+        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
         let (odoo, o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: json!([]), ..Default::default() }).await;
         let set = InflightSet::default();
         let mut a = lane(&url, odoo.clone(), 1, set.clone()).await;
diff --git a/scaas-node/tests/e2e.rs b/scaas-node/tests/e2e.rs
index f8fe9b4..ed9681d 100644
--- a/scaas-node/tests/e2e.rs
+++ b/scaas-node/tests/e2e.rs
@@ -23,13 +23,13 @@ use axum::extract::{Path, State};
 use axum::http::StatusCode;
 use axum::routing::post;
 use axum::{Json, Router};
-use scaas_node::abi::{IMetaToken, IOpenFactory, MetaTransaction};
+use scaas_node::abi::{IToken, MetaTransfer};
 use scaas_node::chain::Chain;
 use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
 use scaas_node::dex::venue::Venue;
 use scaas_node::dex::{cancel_digest, domain, order_hash, Order, WireOrder};
 use scaas_node::gateway::{router, AppState, GwChain};
-use scaas_node::metatx::{digest, Domain, WireMetaTx, MODE_RESTRICT_RELAYER};
+use scaas_node::metatx::{Domain, Mtx, MODE_RESTRICT_RELAYER};
 use scaas_node::odoo::Odoo;
 use scaas_node::submit::{work_from_job, Submitter, Work, BUMP_SKIPPED_CONSUMED};
 use serde_json::{json, Value};
@@ -256,17 +256,39 @@ fn odoo_at(addr: SocketAddr) -> Odoo {
 
 async fn balance(rpc: &str, token: Address, who: Address) -> U256 {
     let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
-    let data = IMetaToken::balanceOfCall { who }.abi_encode();
+    let data = IToken::balanceOfCall { who }.abi_encode();
     let out = p.call(TransactionRequest::default().to(token).input(data.into())).await.unwrap();
     U256::abi_decode(&out).unwrap()
 }
 
-fn sign(signer: &PrivateKeySigner, chain_id: u64, token: Address, m: &MetaTransaction) -> String {
-    let d = Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id, verifying_contract: token };
-    let sig = signer.sign_hash_sync(&digest(&d, m)).unwrap();
+/// The token's salted domain: `chain_uid` from the deploy JSON (the script checked it against block 0).
+fn token_domain(dep: &Value, chain_id: u64, token: Address) -> Domain {
+    Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id, verifying_contract: token,
+             salt: dep["chain_uid"].as_str().unwrap().parse().unwrap() }
+}
+
+fn sign(signer: &PrivateKeySigner, d: &Domain, m: &Mtx) -> String {
+    let sig = signer.sign_hash_sync(&m.digest(d)).unwrap();
     format!("0x{}", alloy::hex::encode(sig.as_bytes()))
 }
 
+/// A payment `MetaTransfer` (`entryRef` = `r`) on lane `batch`.
+#[allow(clippy::too_many_arguments)]
+fn payment(from: Address, to: Address, value: u64, r: B256, batch: U256, mode: u32, relayer: Address, fee: u64,
+    fee_recipient: Address) -> Mtx
+{
+    Mtx::Transfer(MetaTransfer {
+        from, to, value: U256::from(value), entryRef: r, batch, nonce: U256::ZERO, validUntil: U256::from(now() + 300),
+        mode, relayer, fee: U256::from(fee), feeRecipient: fee_recipient,
+    })
+}
+
+/// An outbox job as the client stores it: `struct` names the signed struct (CTR-MTX-15).
+fn job(id: i64, token: Address, m: &Mtx, digest: &str, signature: String) -> Value {
+    let (kind, wire) = m.to_wire();
+    json!({"id": id, "token": format!("{token:#x}"), "digest": digest, "signature": signature, "struct": kind, "metatx": wire})
+}
+
 #[tokio::test]
 #[ignore]
 async fn outbox_payment_reaches_chain_and_comes_back_final() {
@@ -279,30 +301,16 @@ async fn outbox_payment_reaches_chain_and_comes_back_final() {
     let relayer = key(RELAYER);
     let shop = Address::repeat_byte(0x5e);
     let entry_ref = keccak256(b"order-1");
-    let mut data = keccak256(b"pay(bytes32)")[..4].to_vec();
-    data.extend_from_slice(entry_ref.as_slice());
-    let m = MetaTransaction {
-        from: payer.address(),
-        to: shop,
-        value: U256::from(250_000_000u64),
-        data: data.into(),
-        batch: U256::from_be_bytes(keccak256(b"lane").0),
-        nonce: U256::ZERO,
-        validUntil: U256::from(now() + 300),
-        mode: MODE_RESTRICT_RELAYER,
-        relayer: relayer.address(),
-        fee: U256::ZERO,
-        feeRecipient: Address::ZERO,
-    };
-    let signature = sign(&payer, chain_id, token, &m);
+    let d = token_domain(&dep, chain_id, token);
+    let m = payment(payer.address(), shop, 250_000_000, entry_ref, U256::from_be_bytes(keccak256(b"lane").0),
+        MODE_RESTRICT_RELAYER, relayer.address(), 0, Address::ZERO);
+    let signature = sign(&payer, &d, &m);
     let state = Arc::new(Mutex::new(FakeOdoo {
         tokens: vec![format!("{token:#x}")],
         receiving: vec![json!({"token": format!("{token:#x}"), "address": format!("{shop:#x}")})],
         ..Default::default()
     }));
-    state.lock().unwrap().jobs.push(json!({
-        "id": 1, "token": format!("{token:#x}"), "digest": "0x", "signature": signature,
-        "metatx": WireMetaTx::from_sol(&m)}));
+    state.lock().unwrap().jobs.push(job(1, token, &m, "0x", signature));
     let addr = start_fake(state.clone()).await;
     let odoo = odoo_at(addr);
     let cfg = chain_cfg(chain_id, &rpc, None);
@@ -335,8 +343,7 @@ async fn outbox_payment_reaches_chain_and_comes_back_final() {
     assert_eq!(pay["entry_ref"], format!("{entry_ref:#x}"));
     assert_eq!(pay["amount"], "250000000");
     let exe = ingested.iter().find(|e| e["event"] == "MetaTransactionExecuted").expect("executed ingested");
-    let d = Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id, verifying_contract: token };
-    assert_eq!(exe["digest"], format!("{:#x}", digest(&d, &m)));
+    assert_eq!(exe["digest"], format!("{:#x}", m.digest(&d)));
     // Drift A (R56): the ERC-20 Transfer to the receiving wallet rides along with the same tx hash, so
     // Odoo can see it is matched by the PaymentSettled.
     let tr = ingested.iter().find(|e| e["event"] == "Transfer").expect("Transfer to the receiving wallet");
@@ -358,9 +365,7 @@ async fn outbox_payment_reaches_chain_and_comes_back_final() {
 
     // Replay of the same signed job: simulation refuses it, but the subject nonce is spent by this very intent (R80)
     // -> `consumed` (classified from the MetaTransactionExecuted log: our lane landed it), never `dead`; no gas spent.
-    state.lock().unwrap().jobs.push(json!({
-        "id": 2, "token": format!("{token:#x}"), "digest": format!("{:#x}", digest(&d, &m)), "signature": sign(&payer, chain_id, token, &m),
-        "metatx": WireMetaTx::from_sol(&m)}));
+    state.lock().unwrap().jobs.push(job(2, token, &m, &format!("{:#x}", m.digest(&d)), sign(&payer, &d, &m)));
     s.poll_outbox().await;
     let last = state.lock().unwrap().reports.last().cloned().unwrap();
     assert_eq!((last["job_id"].as_i64(), last["chain_state"].as_str(), last["error"].as_str()), (Some(2), Some("consumed"), Some("landed")), "{last}");
@@ -417,6 +422,8 @@ async fn drain(s: &mut Submitter, rx: &mut mpsc::Receiver<Work>) {
 alloy::sol! {
     function setMarket(address tokenA, address tokenB, (bool,bool,uint32,uint32,address) m) external;
     function filled(bytes32 h) external view returns (uint256);
+    function createMetaToken(uint64 version, address underlying, bytes initData, bytes32 salt) external returns (address token);
+    function approve(address spender, uint256 value) external returns (bool);
 }
 
 #[tokio::test]
@@ -428,19 +435,27 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
     let alice = small_key(0xA11CE);
     let bob = small_key(0xB0B);
     let dep = deploy(&rpc, chain_id, alice.address());
-    let token_a: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
+    let demo: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
     let factory: Address = dep["factory"].as_str().unwrap().parse().unwrap();
     let dex: Address = dep["scaas_dex"].as_str().unwrap().parse().unwrap();
 
-    // Quote token B, half to bob — plain txs from the funded deployer (= DEX admin).
+    // Base A (half to alice) and quote B (half to bob): v1 MetaTokens, because the built venue settles `SCaaSDexV1`
+    // over allowances until it moves to `SCaaSDex` (Task 4). Plain txs from the funded deployer (= DEX admin).
     let deployer = key(DEPLOYER);
     let p = ProviderBuilder::new().wallet(EthereumWallet::from(deployer.clone())).connect_http(rpc.parse().unwrap());
-    let init = ("Token BBB".to_string(), "BBB".to_string(), U256::from(6u8), U256::from(1_000_000_000u64), Address::ZERO).abi_encode_params();
-    let create = IOpenFactory::createMetaTokenCall { version: 1, underlying: Address::ZERO, initData: init.into(), salt: B256::repeat_byte(0xbb) };
-    let out = p.call(TransactionRequest::default().to(factory).input(create.abi_encode().into())).await.unwrap();
-    let token_b = Address::abi_decode(&out).unwrap();
-    send(&rpc, &deployer, factory, create.abi_encode()).await;
-    send(&rpc, &deployer, token_b, IMetaToken::transferCall { to: bob.address(), value: U256::from(500_000_000u64) }.abi_encode()).await;
+    let mut v1 = vec![];
+    for (name, supply, salt, holder) in [("AAA", 1_000_000_000_000u64, 0xaa, &alice), ("BBB", 1_000_000_000, 0xbb, &bob)] {
+        let init = (format!("Token {name}"), name.to_string(), U256::from(6u8), U256::from(supply), Address::ZERO).abi_encode_params();
+        let create = createMetaTokenCall { version: 1, underlying: Address::ZERO, initData: init.into(), salt: B256::repeat_byte(salt) };
+        let out = p.call(TransactionRequest::default().to(factory).input(create.abi_encode().into())).await.unwrap();
+        let t = Address::abi_decode(&out).unwrap();
+        send(&rpc, &deployer, factory, create.abi_encode()).await;
+        send(&rpc, &deployer, t, IToken::transferCall { to: holder.address(), value: U256::from(supply / 2) }.abi_encode()).await;
+        let _: Value = p.raw_request("anvil_setBalance".into(), (holder.address(), "0xde0b6b3a7640000")).await.unwrap();
+        send(&rpc, holder, t, approveCall { spender: dex, value: U256::MAX }.abi_encode()).await;
+        v1.push(t);
+    }
+    let (token_a, token_b) = (v1[0], v1[1]);
     let fee_to = Address::repeat_byte(0xfe);
     send(&rpc, &deployer, dex, setMarketCall { tokenA: token_a, tokenB: token_b, m: (true, true, 1_000, 2_000, fee_to) }.abi_encode()).await;
 
@@ -462,7 +477,7 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
     let venue = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
     let (tx, mut rx) = mpsc::channel::<Work>(16);
     let fee_wallet = Address::repeat_byte(0xfa);
-    let gw = GwChain { chain: shared.clone(), tx, tokens: Arc::new(RwLock::new(vec![token_a, token_b])), dex: Some(venue.clone()), breaker: None, fee_recipient: Some(fee_wallet) };
+    let gw = GwChain { chain: shared.clone(), tx, tokens: Arc::new(RwLock::new(vec![token_a, token_b, demo])), dex: Some(venue.clone()), breaker: None, fee_recipient: Some(fee_wallet) };
     let app = router(AppState { chains: Arc::new([(chain_id, gw)].into_iter().collect()) });
     let listener = tokio::net::TcpListener::bind("127.0.0.1:18651").await.unwrap();
     tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
@@ -477,36 +492,17 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
         }
     };
 
-    // 1. Gasless approve (MetaToken op, R26/R35) through the open gateway.
-    for (who, token) in [(&alice, token_a), (&bob, token_b)] {
-        let mut data = keccak256(b"approve(address,uint256)")[..4].to_vec();
-        data.extend((dex, U256::MAX).abi_encode_params());
-        let m = MetaTransaction {
-            from: who.address(), to: dex, value: U256::ZERO, data: data.into(),
-            batch: U256::from_be_bytes(keccak256(b"scaas.dex.approve").0), nonce: U256::ZERO,
-            validUntil: U256::from(now() + 300), mode: MODE_RESTRICT_RELAYER, relayer: relayer.address(),
-            fee: U256::ZERO, feeRecipient: Address::ZERO,
-        };
-        let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": token, "m": WireMetaTx::from_sol(&m),
-            "signature": sign(who, chain_id, token, &m)})).await;
-        assert_eq!(st, 202, "{body}");
-    }
-    drain(&mut s, &mut rx).await;
-
-    // 1b. R84 (review C1): `feeRecipient`/`relayer` of an open-mode intent are not signed, so a client can put
-    //     anything there; the fee still lands in our configured wallet.
+    // 1. R84 (review C1): `feeRecipient`/`relayer` of an open-mode `MetaTransfer` are not signed, so a client can put
+    //    anything there; through the open gateway the fee still lands in our configured wallet.
     let thief = Address::repeat_byte(0x7e);
-    let m = MetaTransaction {
-        from: alice.address(), to: Address::repeat_byte(0x5e), value: U256::from(1_000_000u64), data: Default::default(),
-        batch: U256::from_be_bytes(keccak256(b"e2e.r84").0), nonce: U256::ZERO, validUntil: U256::from(now() + 300),
-        mode: 0x20, // FIXED fee, neither relayer nor fee recipient bound
-        relayer: thief, fee: U256::from(1_000u64), feeRecipient: thief,
-    };
-    let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": token_a, "m": WireMetaTx::from_sol(&m),
-        "signature": sign(&alice, chain_id, token_a, &m)})).await;
+    let m = payment(alice.address(), Address::repeat_byte(0x5e), 1_000_000, B256::ZERO,
+        U256::from_be_bytes(keccak256(b"e2e.r84").0), 0x20, thief, 1_000, thief); // FIXED fee, nothing bound
+    let (kind, wire) = m.to_wire();
+    let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": demo, "struct": kind, "m": wire,
+        "signature": sign(&alice, &token_domain(&dep, chain_id, demo), &m)})).await;
     assert_eq!(st, 202, "{body}");
     drain(&mut s, &mut rx).await;
-    assert_eq!((balance(&rpc, token_a, fee_wallet).await, balance(&rpc, token_a, thief).await), (U256::from(1_000u64), U256::ZERO));
+    assert_eq!((balance(&rpc, demo, fee_wallet).await, balance(&rpc, demo, thief).await), (U256::from(1_000u64), U256::ZERO));
 
     let d = domain(chain_id, dex);
     let place = |o: Order, signer: &PrivateKeySigner| {
@@ -633,26 +629,12 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
     assert_eq!(venue3.rows().await, rows);
 }
 
-fn pay_job(payer: &PrivateKeySigner, chain_id: u64, token: Address, id: i64, tag: &[u8]) -> Value {
+fn pay_job(payer: &PrivateKeySigner, dep: &Value, chain_id: u64, token: Address, id: i64, tag: &[u8]) -> Value {
     let entry_ref = keccak256(tag);
-    let mut data = keccak256(b"pay(bytes32)")[..4].to_vec();
-    data.extend_from_slice(entry_ref.as_slice());
-    let m = MetaTransaction {
-        from: payer.address(),
-        to: Address::repeat_byte(0x5e),
-        value: U256::from(1_000u64),
-        data: data.into(),
-        batch: U256::from_be_bytes(entry_ref.0),
-        nonce: U256::ZERO,
-        validUntil: U256::from(now() + 300),
-        mode: 0,
-        relayer: Address::ZERO,
-        fee: U256::ZERO,
-        feeRecipient: Address::ZERO,
-    };
-    let d = Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id, verifying_contract: token };
-    json!({"id": id, "token": format!("{token:#x}"), "digest": format!("{:#x}", digest(&d, &m)),
-           "signature": sign(payer, chain_id, token, &m), "metatx": WireMetaTx::from_sol(&m)})
+    let m = payment(payer.address(), Address::repeat_byte(0x5e), 1_000, entry_ref, U256::from_be_bytes(entry_ref.0), 0,
+        Address::ZERO, 0, Address::ZERO);
+    let d = token_domain(dep, chain_id, token);
+    job(id, token, &m, &format!("{:#x}", m.digest(&d)), sign(payer, &d, &m))
 }
 
 /// R80 (S2, review H3): another relayer lands OUR intent. (1) While our tx is pending (dropped from anvil's pool so the
@@ -692,7 +674,7 @@ async fn a_peer_landing_our_intent_makes_the_job_consumed_never_dead() {
     let error = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).unwrap()["error"].clone();
 
     // (1) Ours pending, the peer's lands.
-    let j1 = pay_job(&payer, chain_id, token, 41, b"r80-stuck");
+    let j1 = pay_job(&payer, &dep, chain_id, token, 41, b"r80-stuck");
     state.lock().unwrap().jobs.push(j1.clone());
     s.poll_outbox().await;
     assert_eq!(states(41), ["signed", "broadcast"]);
@@ -724,7 +706,7 @@ async fn a_peer_landing_our_intent_makes_the_job_consumed_never_dead() {
     assert_eq!(p.get_transaction_count(relayer.address()).await.unwrap(), 1, "R18: no outer nonce abandoned");
 
     // (2) Same block, the peer outbids our tip: our tx is mined and reverts.
-    let j2 = pay_job(&payer, chain_id, token, 42, b"r80-race");
+    let j2 = pay_job(&payer, &dep, chain_id, token, 42, b"r80-race");
     state.lock().unwrap().jobs.push(j2.clone());
     s.poll_outbox().await;
     assert_eq!(states(42), ["signed", "broadcast"]);
@@ -784,9 +766,9 @@ async fn evm_adapter_runs_the_generic_lane_runner_on_two_mnemonic_lanes() {
 
     let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
     let odoo = odoo_at(start_fake(state.clone()).await);
-    state.lock().unwrap().jobs.push(pay_job(&payer, chain_id, token, 11, b"generic-1"));
+    state.lock().unwrap().jobs.push(pay_job(&payer, &dep, chain_id, token, 11, b"generic-1"));
     assert!(lane_step(&adapter, &odoo, 0, "e2e#0").await.unwrap());
-    state.lock().unwrap().jobs.push(pay_job(&payer, chain_id, token, 12, b"generic-2"));
+    state.lock().unwrap().jobs.push(pay_job(&payer, &dep, chain_id, token, 12, b"generic-2"));
     assert!(lane_step(&adapter, &odoo, 1, "e2e#1").await.unwrap());
     assert!(!lane_step(&adapter, &odoo, 1, "e2e#1").await.unwrap(), "nothing left");
 
diff --git a/scaas-node/tests/e2e_hedera.rs b/scaas-node/tests/e2e_hedera.rs
index 925cdaf..fe83a0d 100644
--- a/scaas-node/tests/e2e_hedera.rs
+++ b/scaas-node/tests/e2e_hedera.rs
@@ -1,7 +1,8 @@
 //! cargo test --test e2e_hedera -- --ignored --nocapture
 //!
 //! Hedera (R63) end to end on a LOCAL devnet stand-in: anvil `--chain-id 298` (Hedera localnet id) with the
-//! HIP-632 precompile 0x16a replaced by `MockHederaAccountService` (smartcontracts/evm/test/hedera/HederaMocks.sol).
+//! HIP-632 precompile 0x16a replaced by `MockHederaAccountService` (smartcontracts/evm/test/hedera/HederaMocks.sol), the
+//! tokens `IS_HEDERA` `NormalToken` clones from `OpenFactory` (`DeployHedera.s.sol`), payments `MetaTransfer`s.
 //! hedera-local-node / solo (≥ 8 GB, many containers) does not run on the shared machine — gap recorded in
 //! docs/history/specs/2026-10-03-net-hedera.md §9. Proven here through the real `HederaAdapter`:
 //! 1. two relayer lanes from a 24-word mnemonic (`m/44'/3030'/0'/0/i`), each with its own key;
@@ -16,7 +17,7 @@ use std::sync::{Arc, Mutex};
 use std::time::Duration;
 
 use alloy::network::EthereumWallet;
-use alloy::primitives::{keccak256, Address, Bytes, U256};
+use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
 use alloy::providers::{Provider, ProviderBuilder};
 use alloy::rpc::types::TransactionRequest;
 use alloy::signers::local::PrivateKeySigner;
@@ -25,12 +26,12 @@ use alloy::sol_types::{SolCall, SolValue};
 use axum::extract::{Path, State};
 use axum::routing::post;
 use axum::{Json, Router};
-use scaas_node::abi::{IMetaToken, MetaTransaction};
+use scaas_node::abi::{IToken, MetaTransfer};
 use scaas_node::adapter::{index_step, lane_step, Family};
 use scaas_node::adapters;
 use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
 use scaas_node::keys::{lane_secret, Seed};
-use scaas_node::metatx::{digest, Domain, WireMetaTx};
+use scaas_node::metatx::{Domain, Mtx};
 use scaas_node::odoo::Odoo;
 use scaas_node::signer::LocalSigner;
 use serde_json::{json, Value};
@@ -201,21 +202,23 @@ fn cfg(rpc: &str) -> ChainCfg {
 
 async fn balance(rpc: &str, token: Address, who: Address) -> U256 {
     let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
-    let data = IMetaToken::balanceOfCall { who }.abi_encode();
+    let data = IToken::balanceOfCall { who }.abi_encode();
     let out = p.call(TransactionRequest::default().to(token).input(data.into())).await.unwrap();
     U256::abi_decode(&out).unwrap()
 }
 
-/// Một thanh toán của tài khoản gốc ký bằng "khoá ED" của nó (mock: chữ ký compact 64 byte).
-fn native_pay(key: &PrivateKeySigner, token: Address, id: i64, tag: &[u8]) -> (Value, MetaTransaction) {
+fn domain(uid: B256, token: Address) -> Domain {
+    Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: CHAIN_ID, verifying_contract: token, salt: uid }
+}
+
+/// A payment `MetaTransfer` of the native account, signed with its "ED key" (mock: 64-byte compact signature).
+fn native_pay(key: &PrivateKeySigner, uid: B256, token: Address, id: i64, tag: &[u8]) -> (Value, Mtx) {
     let entry_ref = keccak256(tag);
-    let mut data = keccak256(b"pay(bytes32)")[..4].to_vec();
-    data.extend_from_slice(entry_ref.as_slice());
-    let m = MetaTransaction {
+    let m = Mtx::Transfer(MetaTransfer {
         from: Address::left_padding_from(&NATIVE.to_be_bytes()),
         to: Address::repeat_byte(0x5e),
         value: U256::from(1_000u64),
-        data: data.into(),
+        entryRef: entry_ref,
         batch: U256::from_be_bytes(keccak256([b"scaas.pay.lane".as_slice(), entry_ref.as_slice()].concat()).0),
         nonce: U256::ZERO,
         validUntil: U256::from(now() + 300),
@@ -223,12 +226,12 @@ fn native_pay(key: &PrivateKeySigner, token: Address, id: i64, tag: &[u8]) -> (V
         relayer: Address::ZERO,
         fee: U256::ZERO,
         feeRecipient: Address::ZERO,
-    };
-    let d = Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: CHAIN_ID, verifying_contract: token };
-    let sig = key.sign_hash_sync(&digest(&d, &m)).unwrap().as_erc2098();
+    });
+    let sig = key.sign_hash_sync(&m.digest(&domain(uid, token))).unwrap().as_erc2098();
     assert_eq!(sig.len(), 64);
-    let job = json!({"id": id, "token": format!("{token:#x}"), "digest": "0x",
-                     "signature": format!("0x{}", alloy::hex::encode(sig)), "metatx": WireMetaTx::from_sol(&m)});
+    let (kind, wire) = m.to_wire();
+    let job = json!({"id": id, "token": format!("{token:#x}"), "digest": "0x", "struct": kind,
+                     "signature": format!("0x{}", alloy::hex::encode(sig)), "metatx": wire});
     (job, m)
 }
 
@@ -246,6 +249,7 @@ async fn hedera_native_account_pays_through_two_lanes_and_never_locks_itself() {
     let dep = deploy(&rpc);
     let t1: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
     let t2: Address = dep["demo_token_2"].as_str().unwrap().parse().unwrap();
+    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
     let native = Address::left_padding_from(&NATIVE.to_be_bytes());
     let native_key = PrivateKeySigner::from_bytes(&keccak256(b"hedera native account key")).unwrap();
 
@@ -284,7 +288,7 @@ async fn hedera_native_account_pays_through_two_lanes_and_never_locks_itself() {
     let odoo = odoo_at(start_fake(state.clone()).await);
 
     // An unfunded lane does not take the job: back to the queue (Hedera accounts must exist and hold HBAR).
-    let (job, m0) = native_pay(&native_key, t1, 20, b"hedera-0");
+    let (job, m0) = native_pay(&native_key, uid, t1, 20, b"hedera-0");
     state.lock().unwrap().jobs.push(job);
     assert!(lane_step(adapter, &odoo, 0, "e2e#0").await.unwrap());
     assert_eq!(states_of(&state, 20), ["queued"]);
@@ -294,15 +298,15 @@ async fn hedera_native_account_pays_through_two_lanes_and_never_locks_itself() {
     for s in &signers {
         let _: Value = p.raw_request("anvil_setBalance".into(), (s.address_hex(), "0xde0b6b3a7640000")).await.unwrap();
     }
-    let (job, _) = native_pay(&native_key, t1, 21, b"hedera-0");
+    let (job, _) = native_pay(&native_key, uid, t1, 21, b"hedera-0");
     state.lock().unwrap().jobs.push(job);
     assert!(lane_step(adapter, &odoo, 0, "e2e#0").await.unwrap());
     assert_eq!(states_of(&state, 21), ["signed", "broadcast", "mined"]);
     assert_eq!(balance(&rpc, t1, Address::repeat_byte(0x5e)).await, U256::from(1_000u64));
 
     // ANTI-LOCK: X (token 1) and Y (token 2) signed by the same subject; X withheld; Y lands; then X.
-    let (x, mx) = native_pay(&native_key, t1, 31, b"hedera-x");
-    let (y, my) = native_pay(&native_key, t2, 32, b"hedera-y");
+    let (x, mx) = native_pay(&native_key, uid, t1, 31, b"hedera-x");
+    let (y, my) = native_pay(&native_key, uid, t2, 32, b"hedera-y");
     state.lock().unwrap().jobs.push(y);
     assert!(lane_step(adapter, &odoo, 1, "e2e#1").await.unwrap());
     assert_eq!(states_of(&state, 32), ["signed", "broadcast", "mined"]);
@@ -318,7 +322,7 @@ async fn hedera_native_account_pays_through_two_lanes_and_never_locks_itself() {
         .filter(|r| r["chain_state"] == "signed").map(|r| r["signer_address"].as_str().unwrap().to_string()).collect();
     assert_eq!(signed_by, signers.iter().map(|s| s.address_hex()).collect());
 
-    // Replay of X: the token's lane nonce is spent, simulation refuses → `consumed` (R80, metaNonce), nothing sent.
+    // Replay of X: the token's lane nonce is spent, simulation refuses → `consumed` (R80, mtxNonce), nothing sent.
     let mut replay = x;
     replay["id"] = json!(33);
     state.lock().unwrap().jobs.push(replay);
@@ -336,8 +340,7 @@ async fn hedera_native_account_pays_through_two_lanes_and_never_locks_itself() {
     let digests: Vec<String> = ingested.iter().filter(|e| e["event"] == "MetaTransactionExecuted")
         .map(|e| e["digest"].as_str().unwrap().to_string()).collect();
     for (t, m) in [(t1, &mx), (t2, &my)] {
-        let d = Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: CHAIN_ID, verifying_contract: t };
-        assert!(digests.contains(&format!("{:#x}", digest(&d, m))));
+        assert!(digests.contains(&format!("{:#x}", m.digest(&domain(uid, t)))));
     }
     let _ = m0;
 }
diff --git a/scaas-node/tests/fuzz.rs b/scaas-node/tests/fuzz.rs
index ba0f481..e3cbccf 100644
--- a/scaas-node/tests/fuzz.rs
+++ b/scaas-node/tests/fuzz.rs
@@ -1,7 +1,7 @@
 //! R54 (GA 2.1#8, spec T15): mọi decoder nhận dữ liệu không tin cậy — body gateway, payload job từ
 //! Odoo, mã hoá meta-tx — không bao giờ panic; dữ liệu xấu là `Err`.
 use scaas_node::dex::WireOrder;
-use scaas_node::metatx::WireMetaTx;
+use scaas_node::metatx::Mtx;
 use scaas_node::odoo::Job;
 use scaas_node::submit::work_from_job;
 use proptest::prelude::*;
@@ -24,13 +24,26 @@ fn any_json() -> impl Strategy<Value = Value> {
     })
 }
 
+/// Either struct's fields (`MetaTransaction` has `data`, `MetaTransfer` has `to`/`value`/`entryRef`), sometimes with a
+/// stray key.
 fn metatx_fields() -> impl Strategy<Value = Value> {
     let s = || prop_oneof!["0x[0-9a-fA-F]{0,70}", "[0-9]{0,90}", ".{0,20}"];
     (s(), s(), s(), s(), s(), s(), s(), s(), any::<u32>(), s(), s(), s()).prop_map(
         |(from, to, value, data, batch, nonce, vu, relayer, mode, fee, fr, extra)| {
-            json!({"from": from, "to": to, "value": value, "data": data, "batch": batch, "nonce": nonce,
-                   "validUntil": vu, "mode": mode, "relayer": relayer, "fee": fee, "feeRecipient": fr,
-                   "x": extra})
+            let shape = extra.len();
+            let mut v = json!({"from": from, "batch": batch, "nonce": nonce, "validUntil": vu, "mode": mode,
+                               "relayer": relayer, "fee": fee, "feeRecipient": fr});
+            if shape & 1 == 0 {
+                v["data"] = json!(data);
+            } else {
+                v["to"] = json!(to);
+                v["value"] = json!(value);
+                v["entryRef"] = json!(extra.clone());
+            }
+            if shape & 6 == 6 {
+                v["x"] = json!(extra);
+            }
+            v
         },
     )
 }
@@ -39,17 +52,17 @@ proptest! {
     #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]
 
     #[test]
-    fn wire_metatx_never_panics(v in metatx_fields()) {
-        if let Ok(w) = serde_json::from_value::<WireMetaTx>(v) {
-            let _ = w.to_sol();
-        }
+    fn wire_metatx_never_panics(v in metatx_fields(), kind in prop_oneof![Just("call".to_string()),
+                                Just("transfer".to_string()), ".{0,8}"]) {
+        let _ = Mtx::from_wire(Some(&kind), &v);
+        let _ = Mtx::from_wire(None, &v);
     }
 
     #[test]
-    fn job_payloads_never_panic(v in any_json(), m in metatx_fields(), sig in ".{0,300}") {
+    fn job_payloads_never_panic(v in any_json(), m in metatx_fields(), sig in ".{0,300}", kind in ".{0,8}") {
         let _ = serde_json::from_value::<Job>(v.clone());
         let shaped = json!({"id": 1, "token": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "signature": sig,
-                            "metatx": m, "call": v});
+                            "struct": kind, "metatx": m, "call": v});
         if let Ok(job) = serde_json::from_value::<Job>(shaped) {
             let _ = work_from_job(&job);
         }
@@ -78,7 +91,8 @@ proptest! {
         use tower::ServiceExt;
         let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
         let app = scaas_node::gateway::router(scaas_node::gateway::AppState::default());
-        let shaped = json!({"chain": 1, "token": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "m": m, "signature": "0x00"});
+        let shaped = json!({"chain": 1, "token": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "m": m, "signature": "0x00",
+                            "struct": "call"});
         for path in ["/v1/metatx", "/v1/dex/orders"] {
             for body in [v.to_string(), shaped.to_string(), raw.clone()] {
                 let req = Request::builder().method("POST").uri(path)
diff --git a/scaas-node/tests/mesh_vectors.rs b/scaas-node/tests/mesh_vectors.rs
index 467d906..3bdf015 100644
--- a/scaas-node/tests/mesh_vectors.rs
+++ b/scaas-node/tests/mesh_vectors.rs
@@ -8,7 +8,7 @@ use alloy::primitives::Address;
 use scaas_node::adapters::{aptos, solana, sui, ton};
 use scaas_node::mesh::accept::{accept, ChainInfo, Ctx, MeshParams, PolicyRow, Seen, Source};
 use scaas_node::mesh::{envelope, hubsig, PeerClass};
-use scaas_node::metatx::{self, Domain, WireMetaTx};
+use scaas_node::metatx::{Domain, Mtx};
 use scaas_node::signer::{Curve, LocalSigner, Signer};
 use ed25519_dalek::SigningKey;
 use serde_json::{json, Value};
@@ -19,6 +19,8 @@ const NOW: u64 = 1_800_000_000;
 const FEE_RECIPIENT: &str = "0x000000000000000000000000000000000000c01d";
 const EVM_LANE: &str = "0x000000000000000000000000000000000000beef"; // = relayer của KAT
 const UNREGISTERED: &str = "0x00000000000000000000000000000000000bad00";
+/// `chain_uid` of chain 7622 (the KATs' salt); the vectors use it for `hedera:296` too.
+const UID: &str = "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464";
 
 // Vector chéo của adapter (cùng bytes ở Move/Python/program) — xem test trong src/adapters/*.rs.
 const SUI_PAYLOAD: &str = "0f73636161732e6d6574616f702e7631086c6f63616c6e6574d4793a1919a40ebfe5587a3a49fe89bb64c54bd49c75ab2a08ac0d5636706382006a749c33bda66662e3709eea404a27dbb2b27d7a58bc0a1248d12436fb2fae71000000000000000000000000000000000000000000000000000000000000beef6400000000000000000000000000000020010101010101010101010101010101010101010101010101010101010101010120a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e8030000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000";
@@ -62,7 +64,7 @@ fn read(path: &str) -> Value {
 }
 
 fn kat() -> Value {
-    read(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/metatx_v1_kat.json"))
+    read(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/metatransfer_kat.json"))
 }
 
 fn ton_vectors() -> Value {
@@ -122,6 +124,7 @@ fn observed(f: &Value, c: &Value) -> Value {
             fee_recipient: evm.then(|| f["fee_recipient"].as_str().unwrap().to_string()),
             program: p["program"].as_str().map(str::to_string),
             wallet_codes,
+            chain_uid: p["chain_uid"].as_str().map(|u| u.parse().unwrap()),
         });
     }
     let policies = match c.get("policy") {
@@ -154,8 +157,8 @@ fn observed(f: &Value, c: &Value) -> Value {
             // R84: đúng thứ submitter sẽ mã hoá — trường không ràng buộc bị ghi đè, digest giữ nguyên.
             let submit = d.evm.as_ref().map(|e| {
                 let mut m = e.meta.clone();
-                metatx::normalize(&mut m, Some(f["fee_recipient"].as_str().unwrap().parse::<Address>().unwrap()));
-                serde_json::to_value(WireMetaTx::from_sol(&m)).unwrap()
+                m.normalize(Some(f["fee_recipient"].as_str().unwrap().parse::<Address>().unwrap()));
+                m.to_wire().1
             });
             json!({
                 "accept": true,
@@ -268,30 +271,37 @@ fn alice_evm() -> LocalSigner {
     LocalSigner::new(Curve::Secp256k1, &k).unwrap()
 }
 
-fn evm_id(chain_key: &str, contract: &str, name: &str, m: &WireMetaTx) -> [u8; 32] {
+/// `m` is a wire `MetaTransfer`, or a wire `MetaTransaction` when it has `data` (`struct = call`).
+fn kind_of(m: &Value) -> &'static str {
+    if m.get("data").is_some() { "call" } else { "transfer" }
+}
+
+fn evm_id(chain_key: &str, contract: &str, name: &str, m: &Value) -> [u8; 32] {
     let domain = Domain {
         name: name.into(),
         version: "1".into(),
         chain_id: chain_key.split_once(':').unwrap().1.parse().unwrap(),
         verifying_contract: contract.parse().unwrap(),
+        salt: UID.parse().unwrap(),
     };
-    metatx::digest(&domain, &m.to_sol().unwrap()).0
+    Mtx::from_wire(Some(kind_of(m)), m).unwrap().digest(&domain).0
 }
 
-fn evm_env_named(chain_key: &str, contract: &str, name: &str, m: &WireMetaTx, sig_kind: &str, signature: Option<String>) -> Value {
+fn evm_env_named(chain_key: &str, contract: &str, name: &str, m: &Value, sig_kind: &str, signature: Option<String>) -> Value {
     let id = evm_id(chain_key, contract, name, m);
     let signature = signature.unwrap_or_else(|| hex0x(&alice_evm().sign(&id).unwrap()));
     let mut env = json!({
         "spec": envelope::SPEC, "intent_id": hex0x(&id), "chain_key": chain_key,
         "family": chain_key.split_once(':').unwrap().0, "contract": contract, "visibility": "open",
-        "evm": {"domain": {"name": name, "version": "1"}, "meta_tx": m, "signature": signature, "sig_kind": sig_kind},
+        "evm": {"domain": {"name": name, "version": "1"}, "struct": kind_of(m), "meta_tx": m, "signature": signature,
+                "sig_kind": sig_kind},
         "hub": {"published_at": NOW}, "hop_count": 0,
     });
     seal(&mut env);
     env
 }
 
-fn evm_env(chain_key: &str, contract: &str, m: &WireMetaTx) -> Value {
+fn evm_env(chain_key: &str, contract: &str, m: &Value) -> Value {
     evm_env_named(chain_key, contract, "SCaaS MetaToken", m, "eoa", None)
 }
 
@@ -328,41 +338,46 @@ fn regenerate() {
     let ks = |f: &str| k[f].as_str().unwrap().to_lowercase();
     let token = ks("verifying_contract");
     let zero = format!("{:#x}", Address::ZERO);
-    let base = WireMetaTx {
-        from: ks("from"), to: ks("to"), value: ks("value"), data: ks("data"), batch: ks("batch"), nonce: "0".into(),
-        valid_until: (NOW + 300).to_string(), mode: 0x20, relayer: zero.clone(), fee: "5000".into(), fee_recipient: zero.clone(),
-    };
-    let m = |f: &dyn Fn(&mut WireMetaTx)| {
+    // A payment `MetaTransfer` (selector `pay`) of the KAT's payer; FIXED fee, nothing bound.
+    let base = json!({
+        "from": ks("from"), "to": ks("to"), "value": ks("value"), "entryRef": ks("entry_ref"), "batch": ks("batch"),
+        "nonce": "0", "validUntil": (NOW + 300).to_string(), "mode": 0x20, "relayer": zero.clone(), "fee": "5000",
+        "feeRecipient": zero.clone(),
+    });
+    let m = |f: &dyn Fn(&mut Value)| {
         let mut x = base.clone();
         f(&mut x);
         x
     };
     let e1 = evm_env("evm:7622", &token, &base);
     let mut cases = vec![
-        case("01_evm_open_fixed_fee", e1.clone(), json!({"accept": true, "fee_effective": "5000", "selector": "0x8609cad1",
+        case("01_evm_open_fixed_fee", e1.clone(), json!({"accept": true, "fee_effective": "5000", "selector": "pay",
              "may_submit": true, "state": "submittable"})),
         case("02_evm_garbage_unbound_fields", evm_env("evm:7622", &token, &m(&|x| {
-            x.relayer = "0x00000000000000000000000000000000deadbeef".into();
-            x.fee_recipient = "0x000000000000000000000000000000000bad0bad".into();
+            x["relayer"] = json!("0x00000000000000000000000000000000deadbeef");
+            x["feeRecipient"] = json!("0x000000000000000000000000000000000bad0bad");
         })), json!({"accept": true, "may_submit": true})),
     ];
-    // 03a: KAT forge nguyên văn (chữ ký do forge ký) — MODE_RESTRICT_RELAYER, relayer = lane của ta.
-    let kat_m = WireMetaTx {
-        from: ks("from"), to: ks("to"), value: ks("value"), data: ks("data"), batch: ks("batch"), nonce: ks("nonce"),
-        valid_until: ks("valid_until"), mode: ks("mode").parse().unwrap(), relayer: ks("relayer"), fee: ks("fee"),
-        fee_recipient: ks("fee_recipient"),
-    };
+    // 03a: KAT forge nguyên văn (chữ ký do forge ký) — relayer and fee recipient bound, relayer = lane của ta.
+    let kat_m = json!({
+        "from": ks("from"), "to": ks("to"), "value": ks("value"), "entryRef": ks("entry_ref"), "batch": ks("batch"),
+        "nonce": ks("nonce"), "validUntil": ks("valid_until"), "mode": ks("mode").parse::<u32>().unwrap(),
+        "relayer": ks("relayer"), "fee": ks("fee"), "feeRecipient": ks("fee_recipient"),
+    });
     cases.push(case("03a_evm_restrict_relayer_our_lane_kat",
         evm_env_named("evm:7622", &token, k["domain_name"].as_str().unwrap(), &kat_m, "eoa", Some(ks("signature"))),
-        json!({"accept": true, "may_submit": true, "fee_effective": "0"})));
+        json!({"accept": true, "may_submit": true, "fee_effective": "100000"})));
     cases.push(case("03b_evm_restrict_relayer_foreign_lane", evm_env("evm:7622", &token, &m(&|x| {
-        x.mode = 0x21;
-        x.relayer = "0x000000000000000000000000000000000000cafe".into();
+        x["mode"] = json!(0x21);
+        x["relayer"] = json!("0x000000000000000000000000000000000000cafe");
     })), json!({"accept": true, "may_submit": false})));
-    cases.push(case("04_evm_restrict_relayer_zero", evm_env("evm:7622", &token, &m(&|x| x.mode = 0x21)), reject("RELAYER_BOUND_ZERO")));
-    cases.push(case("05_evm_empty_data", evm_env("evm:7622", &token, &m(&|x| x.data = "0x".into())),
-        json!({"accept": true, "selector": "0x"})));
-    let wallet = m(&|x| x.from = "0x0000000000000000000000000000000000001271".into());
+    cases.push(case("04_evm_restrict_relayer_zero", evm_env("evm:7622", &token, &m(&|x| x["mode"] = json!(0x21))),
+        reject("RELAYER_BOUND_ZERO")));
+    // 05: a plain transfer `MetaTransfer` (`entryRef = 0`): selector `transfer` (case 01 is a payment: `pay`).
+    cases.push(case("05_evm_transfer", evm_env("evm:7622", &token,
+        &m(&|x| x["entryRef"] = json!(format!("{:#x}", alloy::primitives::B256::ZERO)))),
+        json!({"accept": true, "selector": "transfer"})));
+    let wallet = m(&|x| x["from"] = json!("0x0000000000000000000000000000000000001271"));
     let e6 = evm_env_named("evm:7622", &token, "SCaaS MetaToken", &wallet, "erc1271", Some(format!("0x{}", "ab".repeat(96))));
     cases.push(case("06_evm_erc1271_no_local_recover", e6.clone(), json!({"accept": true, "may_submit": true})));
     // 07: cùng chữ ký case 01 nhưng s → n − s (v lật): khôi phục đúng người ký, contract vẫn từ chối.
@@ -471,9 +486,9 @@ fn regenerate() {
     cases.push(case("16_unknown_top_level_field", with(e1.clone(), "x_future", json!({"anything": [1, 2]})),
         json!({"accept": true, "may_submit": true})));
     cases.push(case("17_hop_limit", with(e1.clone(), "hop_count", json!(4)), reject("HOP_LIMIT")));
-    cases.push(case("18a_valid_too_long", evm_env("evm:7622", &token, &m(&|x| x.valid_until = (NOW + 3601).to_string())),
+    cases.push(case("18a_valid_too_long", evm_env("evm:7622", &token, &m(&|x| x["validUntil"] = json!((NOW + 3601).to_string()))),
         reject("VALID_TOO_LONG")));
-    cases.push(case("18b_expired_inside_skew", evm_env("evm:7622", &token, &m(&|x| x.valid_until = (NOW + 10).to_string())),
+    cases.push(case("18b_expired_inside_skew", evm_env("evm:7622", &token, &m(&|x| x["validUntil"] = json!((NOW + 10).to_string()))),
         reject("EXPIRED")));
     let mut e19 = e1.clone();
     let mut id = alloy::hex::decode(e1["intent_id"].as_str().unwrap()).unwrap();
@@ -520,8 +535,8 @@ fn regenerate() {
     let pol = |contract: &str, min_fee: &str| json!([{"chain_key": "evm:7622", "contract": contract, "selector": "*", "support": "full",
         "submit": true, "pool_visibility": "open", "min_fee": min_fee, "fee_recipient_allow": "any"}]);
     cases.push(with(case("29_none_mode_huge_fee", evm_env("evm:7622", &token, &m(&|x| {
-        x.mode = 0x00;
-        x.fee = format!("1{}", "0".repeat(30));
+        x["mode"] = json!(0x00);
+        x["fee"] = json!(format!("1{}", "0".repeat(30)));
     })), json!({"accept": true, "fee_effective": "0", "may_submit": false})), "policy", pol(&token, "1")));
     cases.push(with(case("30_unregistered_contract", evm_env("evm:7622", UNREGISTERED, &base),
         json!({"accept": true, "token": UNREGISTERED, "may_submit": false})), "policy", pol(UNREGISTERED, "0")));
@@ -553,7 +568,8 @@ fn regenerate() {
         "params": {"max_hops": 4, "clock_skew_secs": 30, "max_valid_for_secs": 3600, "exclusive_ms": 10000},
         "tokens": tokens,
         "lanes": lanes,
-        "chain_params": {"aptos:4": {"program": APTOS_PACKAGE}, sol_chain: {"program": SOL_PROGRAM},
+        "chain_params": {"evm:7622": {"chain_uid": UID}, "hedera:296": {"chain_uid": UID},
+                         "aptos:4": {"program": APTOS_PACKAGE}, sol_chain: {"program": SOL_PROGRAM},
                          "ton:-239": {"wallet_codes": {master.raw(): {"hash": alloy::hex::encode(code), "depth": depth}}}},
         "cases": [],
     });
diff --git a/smartcontracts/evm/script/Deploy.s.sol b/smartcontracts/evm/script/Deploy.s.sol
index de68281..c8bc5bb 100644
--- a/smartcontracts/evm/script/Deploy.s.sol
+++ b/smartcontracts/evm/script/Deploy.s.sol
@@ -9,6 +9,7 @@ import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
 import {SmartKeyAccountFactory} from "../src/account/SmartKeyAccountFactory.sol";
 import {SCaaSDexV1} from "../src/dex/SCaaSDexV1.sol";
 import {DeployBase} from "./DeployBase.sol";
+import {OpenFactory} from "../src/factory/OpenFactory.sol";
 
 /// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --sender <địa chỉ deployer = vm.addr(PRIVATE_KEY)>
 /// env: PRIVATE_KEY (deployer; registrar mặc định), REGISTRAR (tuỳ chọn),
@@ -32,16 +33,11 @@ contract Deploy is DeployBase {
         _gate(address(accounts));
         MetaToken impl = new MetaToken{salt: salt}(address(factory), accounts.IMPLEMENTATION());
         if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
-        _deployTokenFactory(registrar, registrar == deployer, accounts.IMPLEMENTATION(), false);
+        OpenFactory tokens = _deployTokenFactory(registrar, registrar == deployer, accounts.IMPLEMENTATION(), false);
         MetaTxDex dex = new MetaTxDex{salt: salt}();
         // R35: admin chỉ `setMarket`; production đặt REGISTRAR là một Safe (RS5-1).
         SCaaSDexV1 scaasDex = new SCaaSDexV1{salt: salt}(registrar);
-        address demo;
-        if (demoSupply != 0 && registrar == deployer) {
-            demo = factory.createMetaToken(1, address(0),
-                abi.encode("SCaaS Demo USD", "bUSD", uint8(6), demoSupply, deployer), bytes32("demo"));
-            if (demoHolder != deployer) MetaToken(demo).transfer(demoHolder, demoSupply / 2);
-        }
+        if (demoSupply != 0 && registrar == deployer) _demoTokens(tokens, demoSupply, deployer, demoHolder);
         vm.stopBroadcast();
 
         string memory k = "deploy";
@@ -50,8 +46,7 @@ contract Deploy is DeployBase {
         vm.serializeAddress(k, "dex", address(dex));
         vm.serializeAddress(k, "smart_key_account_factory", address(accounts));
         vm.serializeAddress(k, "smart_key_account_implementation", accounts.IMPLEMENTATION());
-        vm.serializeAddress(k, "scaas_dex", address(scaasDex));
-        string memory out = vm.serializeAddress(k, "demo_token", demo);
+        string memory out = vm.serializeAddress(k, "scaas_dex", address(scaasDex));
         vm.createDir("./deployments", true);
         vm.writeJson(out, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
         console.log(out);
diff --git a/smartcontracts/evm/script/DeployBase.sol b/smartcontracts/evm/script/DeployBase.sol
index f7ed54c..a716858 100644
--- a/smartcontracts/evm/script/DeployBase.sol
+++ b/smartcontracts/evm/script/DeployBase.sol
@@ -4,6 +4,9 @@ pragma solidity ^0.8.24;
 import {Script} from "forge-std/Script.sol";
 import {OpenFactory} from "../src/factory/OpenFactory.sol";
 import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
+import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
+import {AdminLib} from "../src/metatx/AdminLib.sol";
+import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
 import {NormalToken} from "../src/metatx/NormalToken.sol";
 import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
 import {UniversalAccountRegistry} from "../src/registry/UniversalAccountRegistry.sol";
@@ -110,6 +113,34 @@ abstract contract DeployBase is Script {
         vm.serializeAddress("deploy", "implementation_wrapped_zether", address(und));
     }
 
+    /// @notice Two kind-`NORMAL` demo tokens from `f` (dev chains; only when the deployer is the registrar): 6 decimals,
+    ///         `PAYABLE`, `supply` each to the deployer, half of each to `holder`; JSON `demo_token`, `demo_token_2`.
+    function _demoTokens(OpenFactory f, uint256 supply, address deployer, address holder)
+        internal returns (address demo, address demo2)
+    {
+        demo = _demoToken(f, "SCaaS Demo USD", "bUSD", supply, deployer, "demo");
+        demo2 = _demoToken(f, "SCaaS Demo Points", "bPTS", supply, deployer, "demo2");
+        if (holder != deployer) {
+            IERC20(demo).transfer(holder, supply / 2);
+            IERC20(demo2).transfer(holder, supply / 2);
+        }
+        vm.serializeAddress("deploy", "demo_token_2", demo2);
+        vm.serializeAddress("deploy", "demo_token", demo);
+    }
+
+    function _demoToken(OpenFactory f, string memory name, string memory symbol, uint256 supply, address holder,
+        bytes32 tokenSalt) private returns (address)
+    {
+        IFactoryToken.TokenConfig memory c;
+        c.name = name;
+        c.symbol = symbol;
+        c.decimals = 6;
+        c.features = 1 << AdminLib.PAYABLE;
+        c.initialSupply = supply;
+        c.initialHolder = holder;
+        return f.createToken(IOpenFactory.TokenKind.NORMAL, 1, c, tokenSalt);
+    }
+
     /// @notice The deploy gate (CTR-GEN-05): `chainUid()` of the deployed contract equals the RPC's genesis hash.
     function _gate(address c) internal view {
         (bool ok, bytes memory ret) = c.staticcall(abi.encodeWithSignature("chainUid()"));
diff --git a/smartcontracts/evm/script/hedera/DeployHedera.s.sol b/smartcontracts/evm/script/hedera/DeployHedera.s.sol
index 02a8165..34168df 100644
--- a/smartcontracts/evm/script/hedera/DeployHedera.s.sol
+++ b/smartcontracts/evm/script/hedera/DeployHedera.s.sol
@@ -4,10 +4,10 @@ pragma solidity ^0.8.20;
 import {console} from "forge-std/Script.sol";
 import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
 import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
-import {MetaToken} from "../../src/metatx/MetaToken.sol";
 import {MetaTxDex} from "../../src/dex/MetaTxDex.sol";
 import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
 import {DeployBase} from "../DeployBase.sol";
+import {OpenFactory} from "../../src/factory/OpenFactory.sol";
 
 /// Như `script/Deploy.s.sol` nhưng implementation META là `HederaMetaToken` (R63).
 /// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow --sender <địa chỉ deployer>`
@@ -28,28 +28,15 @@ contract DeployHedera is DeployBase {
         OpenFactoryV1 factory = new OpenFactoryV1{salt: salt}(registrar);
         HederaMetaToken impl = new HederaMetaToken{salt: salt}(address(factory));
         if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
-        _deployTokenFactory(registrar, registrar == deployer, address(0), true);
+        OpenFactory tokens = _deployTokenFactory(registrar, registrar == deployer, address(0), true);
         MetaTxDex dex = new MetaTxDex{salt: salt}();
-        address demo;
-        address demo2;
-        if (demoSupply != 0 && registrar == deployer) {
-            demo = factory.createMetaToken(1, address(0),
-                abi.encode("SCaaS Demo USD", "bUSD", uint8(6), demoSupply, deployer), bytes32("demo"));
-            demo2 = factory.createMetaToken(1, address(0),
-                abi.encode("SCaaS Demo Points", "bPTS", uint8(6), demoSupply, deployer), bytes32("demo2"));
-            if (demoHolder != deployer) {
-                MetaToken(demo).transfer(demoHolder, demoSupply / 2);
-                MetaToken(demo2).transfer(demoHolder, demoSupply / 2);
-            }
-        }
+        if (demoSupply != 0 && registrar == deployer) _demoTokens(tokens, demoSupply, deployer, demoHolder);
         vm.stopBroadcast();
 
         string memory k = "deploy";
         vm.serializeAddress(k, "factory", address(factory));
         vm.serializeAddress(k, "implementation", address(impl));
-        vm.serializeAddress(k, "dex", address(dex));
-        vm.serializeAddress(k, "demo_token_2", demo2);
-        string memory out = vm.serializeAddress(k, "demo_token", demo);
+        string memory out = vm.serializeAddress(k, "dex", address(dex));
         vm.createDir("./deployments", true);
         vm.writeJson(out, string.concat("./deployments/hedera-", vm.toString(block.chainid), ".json"));
         console.log(out);
diff --git a/smartcontracts/evm/test/hedera/HederaKat.t.sol b/smartcontracts/evm/test/hedera/HederaKat.t.sol
index c1e8d1a..180f914 100644
--- a/smartcontracts/evm/test/hedera/HederaKat.t.sol
+++ b/smartcontracts/evm/test/hedera/HederaKat.t.sol
@@ -1,37 +1,62 @@
 // SPDX-License-Identifier: Apache-2.0
-pragma solidity ^0.8.20;
+pragma solidity ^0.8.24;
 
-import {console} from "forge-std/console.sol";
-import {stdJson} from "forge-std/StdJson.sol";
+import {Test} from "forge-std/Test.sol";
+import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
+import {NormalToken} from "../../src/metatx/NormalToken.sol";
+import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
 import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
-import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
-import {HederaFixture} from "./HederaMetaToken.t.sol";
+import {normalInit} from "../v2/helpers/V2Fixture.sol";
 
-/// @title Vector chung Hedera (Python ở Odoo, Rust ở node, Solidity ở đây).
-/// @notice `test/vectors/hedera_kat.json` sinh bởi `test/hedera/gen_hedera_kat.py` (digest EIP-712 theo
-///         `dms_blockchain/lib/eip712.py` + chữ ký ed25519 THẬT RFC 8032 trên digest, khoá từ seed cố định).
-///         Ở đây: cùng kịch bản phải ra cùng địa chỉ token và cùng digest. Toán ed25519 của chữ ký được Python
-///         (`cryptography`) và Rust (`ed25519-dalek`) kiểm; precompile HIP-632 trên Hedera kiểm đúng phép đó.
-contract HederaKatTest is HederaFixture {
-    using stdJson for string;
+/// The Hedera vector (NET-HED-03, CTR-TOK-23): a payment `MetaTransfer` of the Hedera account 0.0.1234567 (long-zero
+/// `from`) on an `IS_HEDERA` `NormalToken` clone on chain 296, in the salted token domain. Forge writes the
+/// struct, digest and relayed calldata (`WRITE_KAT=true forge test --match-contract HederaKatTest`), then
+/// `python3 test/hedera/gen_hedera_kat.py` adds the RFC 8032 ed25519 signature over the digest (the bytes HIP-632's
+/// `isAuthorizedRaw` checks); scaas-node (`adapters::hedera` tests) verifies both. The v1 vector is in `legacy/p5/`.
+contract HederaKatTest is Test {
+    using MetaTxLib for MetaTxLib.MetaTransfer;
 
-    function test_katDigestMatchesPythonAndRust() public {
-        _setUpHedera();
-        HederaMetaToken tok = _token("HBUSD", 0);
-        console.log("verifying_contract", address(tok));
-        string memory j = vm.readFile("./test/vectors/hedera_kat.json");
-        assertEq(address(tok), j.readAddress(".verifying_contract"));
-        assertEq(block.chainid, j.readUint(".chain_id"));
-        bytes32 ref = j.readBytes32(".entry_ref");
-        MetaTxLib.LegacyMetaTransaction memory m = MetaTxLib.LegacyMetaTransaction({
-            from: j.readAddress(".from"), to: j.readAddress(".to"), value: j.readUint(".value"),
-            data: j.readBytes(".data"), batch: j.readUint(".batch"), nonce: 0,
-            validUntil: j.readUint(".valid_until"), mode: uint32(j.readUint(".mode")),
-            relayer: j.readAddress(".relayer"), fee: 0, feeRecipient: address(0)
+    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
+    address internal constant NATIVE = address(uint160(1_234_567)); // 0.0.1234567
+    string internal constant OUT = "./test/vectors/hedera_kat.json";
+
+    function test_hederaKat() public {
+        vm.chainId(296);
+        NormalToken tok =
+            NormalToken(Clones.clone(address(new NormalToken(address(this), address(0), UID, true))));
+        tok.initialize(address(this), 1, normalInit("HBUSD", "HBUSD", 6, 0, address(this), address(0)));
+        bytes32 ref = bytes32(uint256(0x42));
+        MetaTxLib.MetaTransfer memory t = MetaTxLib.MetaTransfer({
+            from: NATIVE, to: address(0x5409), value: 250_000_000, entryRef: ref, batch: tok.payLane(ref), nonce: 0,
+            validUntil: 1_800_000_300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: address(0xBEEF), fee: 0,
+            feeRecipient: address(0)
         });
-        assertEq(m.data, abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), ref));
-        assertEq(m.batch, uint256(keccak256(abi.encodePacked("scaas.pay.lane", ref))));
-        assertEq(tok.metaTxDigest(m), j.readBytes32(".digest"));
-        assertEq(j.readBytes(".ed25519_signature").length, 64);
+        bytes32 digest = tok.mtxTransferDigest(t);
+        string memory k = "hedera";
+        vm.serializeString(k, "chain_id", "296");
+        vm.serializeString(k, "hedera_account", "0.0.1234567");
+        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
+        vm.serializeString(k, "salt", vm.toString(UID));
+        vm.serializeString(k, "from", vm.toString(t.from));
+        vm.serializeString(k, "to", vm.toString(t.to));
+        vm.serializeString(k, "value", vm.toString(t.value));
+        vm.serializeString(k, "entry_ref", vm.toString(t.entryRef));
+        vm.serializeString(k, "batch", vm.toString(t.batch));
+        vm.serializeString(k, "nonce", "0");
+        vm.serializeString(k, "valid_until", vm.toString(t.validUntil));
+        vm.serializeString(k, "mode", vm.toString(uint256(t.mode)));
+        vm.serializeString(k, "relayer", vm.toString(t.relayer));
+        vm.serializeString(k, "struct_hash", vm.toString(t.hashStruct()));
+        string memory out = vm.serializeString(k, "digest", vm.toString(digest));
+        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);
+
+        string memory onDisk = vm.readFile(OUT);
+        string[] memory keys = vm.parseJsonKeys(out, "$");
+        assertEq(keys.length, 15);
+        for (uint256 i; i < keys.length; ++i) {
+            assertEq(vm.parseJsonString(onDisk, string.concat(".", keys[i])),
+                vm.parseJsonString(out, string.concat(".", keys[i])), keys[i]);
+        }
+        if (!vm.envOr("WRITE_KAT", false)) assertEq(vm.parseJsonBytes(onDisk, ".ed25519_signature").length, 64);
     }
 }
diff --git a/smartcontracts/evm/test/hedera/gen_hedera_kat.py b/smartcontracts/evm/test/hedera/gen_hedera_kat.py
index a322b5b..b213170 100644
--- a/smartcontracts/evm/test/hedera/gen_hedera_kat.py
+++ b/smartcontracts/evm/test/hedera/gen_hedera_kat.py
@@ -1,57 +1,29 @@
 #!/usr/bin/env python3
-"""Sinh `test/vectors/hedera_kat.json` — vector chung Hedera (R63).
+"""Add the ed25519 fields to `test/vectors/hedera_kat.json` (the Hedera vector, NET-HED-03).
 
-python3 test/hedera/gen_hedera_kat.py   (từ thư mục smartcontracts/evm/)
+    WRITE_KAT=true forge test --match-contract HederaKatTest   # writes the struct, digest (salted MetaTransfer)
+    python3 test/hedera/gen_hedera_kat.py                       # from smartcontracts/evm/: signs that digest
 
-Digest EIP-712 tính bằng chính `dms_blockchain/lib/eip712.py` (bản Odoo dùng thật); chữ ký ed25519 RFC 8032 trên
-32 byte digest (đúng phép mà HIP-632 `isAuthorizedRaw` kiểm), khoá từ seed cố định. `HederaKat.t.sol` kiểm digest
-khớp Solidity; Odoo (`test_hedera.py`) và Rust (`adapters::hedera` tests) kiểm digest + chữ ký.
+RFC 8032 ed25519 over the 32 digest bytes (exactly what HIP-632 `isAuthorizedRaw` checks), key from a fixed seed.
+`HederaKatTest` checks the forge fields; scaas-node (`adapters::hedera` tests) checks digest and signature.
 """
 import hashlib
-import importlib
 import json
 import os
-import sys
-import types
 
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
 
-HERE = os.path.dirname(os.path.abspath(__file__))
-_pkg = types.ModuleType('dmslib')  # nạp lib mà không chạy lib/__init__ (kéo Odoo)
-_pkg.__path__ = [os.path.join(HERE, '..', '..', '..', '..', '..', 'dms_blockchain', 'lib')]
-sys.modules['dmslib'] = _pkg
-eip712 = importlib.import_module('dmslib.eip712')
-
-# Địa chỉ clone mà HederaKat.t.sol deploy (chainId 296, factory đầu tiên của test contract, salt keccak("HBUSD")).
-TOKEN = '0x284f66c17c0e60a8f75903af8f185b0a8d8b770c'
-ACCOUNT_NUM = 1_234_567                                   # 0.0.1234567
+PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'vectors', 'hedera_kat.json')
 SEED = hashlib.sha256(b'scaas.hedera.kat.v1').digest()
 
-ref = bytes(31) + b'\x42'
-m = {
-    'from': '0x' + ACCOUNT_NUM.to_bytes(20, 'big').hex(), 'to': '0x' + '00' * 18 + '5409',
-    'value': 250_000_000, 'data': eip712.pay_data(ref), 'batch': eip712.lane_batch(ref), 'nonce': 0,
-    'valid_until': 1_800_000_300, 'mode': eip712.MODE_RESTRICT_RELAYER,
-    'relayer': '0x' + '00' * 18 + 'beef', 'fee': 0, 'fee_recipient': eip712.ZERO_ADDRESS,
-}
-domain = {'name': 'SCaaS MetaToken', 'version': '1', 'chain_id': 296, 'verifying_contract': TOKEN}
-digest = eip712.digest(domain, m)
+with open(PATH) as f:
+    kat = json.load(f)
+digest = bytes.fromhex(kat['digest'][2:])
 sk = Ed25519PrivateKey.from_private_bytes(SEED)
-pk = sk.public_key().public_bytes_raw()
-sig = sk.sign(digest)
-out = {
-    '_doc': 'Hedera KAT: EIP-712 MetaTransaction digest (HederaMetaToken, chain 296) signed with ed25519 by '
-            'Hedera account 0.0.1234567 (long-zero from). Generated by test/hedera/gen_hedera_kat.py.',
-    'chain_id': 296, 'hedera_account': f'0.0.{ACCOUNT_NUM}', 'verifying_contract': TOKEN,
-    'from': m['from'], 'to': m['to'], 'value': str(m['value']), 'entry_ref': '0x' + ref.hex(),
-    'data': '0x' + m['data'].hex(), 'batch': str(m['batch']), 'nonce': '0',
-    'valid_until': str(m['valid_until']), 'mode': str(m['mode']), 'relayer': m['relayer'],
-    'struct_hash': '0x' + eip712.struct_hash(m).hex(), 'digest': '0x' + digest.hex(),
-    'ed25519_seed': '0x' + SEED.hex(), 'ed25519_public_key': '0x' + pk.hex(),
-    'ed25519_signature': '0x' + sig.hex(),
-}
-path = os.path.join(HERE, '..', 'vectors', 'hedera_kat.json')
-with open(path, 'w') as f:
-    json.dump(out, f, indent=2)
+kat['ed25519_seed'] = '0x' + SEED.hex()
+kat['ed25519_public_key'] = '0x' + sk.public_key().public_bytes_raw().hex()
+kat['ed25519_signature'] = '0x' + sk.sign(digest).hex()
+with open(PATH, 'w') as f:
+    json.dump(kat, f, indent=2, sort_keys=True)
     f.write('\n')
-print(path)
+print(PATH)
diff --git a/smartcontracts/evm/test/vectors/hedera_kat.json b/smartcontracts/evm/test/vectors/hedera_kat.json
index 1fa4d20..660dce6 100644
--- a/smartcontracts/evm/test/vectors/hedera_kat.json
+++ b/smartcontracts/evm/test/vectors/hedera_kat.json
@@ -1,21 +1,20 @@
 {
-  "_doc": "Hedera KAT: EIP-712 MetaTransaction digest (HederaMetaToken, chain 296) signed with ed25519 by Hedera account 0.0.1234567 (long-zero from). Generated by test/hedera/gen_hedera_kat.py.",
-  "chain_id": 296,
-  "hedera_account": "0.0.1234567",
-  "verifying_contract": "0x284f66c17c0e60a8f75903af8f185b0a8d8b770c",
-  "from": "0x000000000000000000000000000000000012d687",
-  "to": "0x0000000000000000000000000000000000005409",
-  "value": "250000000",
-  "entry_ref": "0x0000000000000000000000000000000000000000000000000000000000000042",
-  "data": "0x8609cad10000000000000000000000000000000000000000000000000000000000000042",
   "batch": "86022544659198444797210540178800705113871287550440015647596849794355165415193",
+  "chain_id": "296",
+  "digest": "0xa3137d1c7904c8e5a041d3f5dc533964b913f49238a7fa7f81c29e4e850f4a6a",
+  "ed25519_public_key": "0x8df25ef87e99177799296d8bfa7ed2397a5f6d96140c77dcc4f55e55711045fe",
+  "ed25519_seed": "0xa29ec2ea2bcdb9db24af6fb04855c1041d9708400a06c1859a026fbeb5391593",
+  "ed25519_signature": "0x4b8c3f8d95e6386cabb08d3a02fdac7ce9bf18c64185d267e8885e779fe66f79e558a2b730884e84ec1030806d26ed8b99bca93675c723afe51b802fc26e1d05",
+  "entry_ref": "0x0000000000000000000000000000000000000000000000000000000000000042",
+  "from": "0x000000000000000000000000000000000012d687",
+  "hedera_account": "0.0.1234567",
+  "mode": "1",
   "nonce": "0",
+  "relayer": "0x000000000000000000000000000000000000bEEF",
+  "salt": "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464",
+  "struct_hash": "0x8df559def30c37b92db2cbe50f1d02382a11111fac8be7cc2c112ffb2197cef0",
+  "to": "0x0000000000000000000000000000000000005409",
   "valid_until": "1800000300",
-  "mode": "1",
-  "relayer": "0x000000000000000000000000000000000000beef",
-  "struct_hash": "0xccd6ae79e2d103ae5d9267f45b60de8595bd4f7d671bdfc7f46f12a62c4e234e",
-  "digest": "0x4571aad8903c76223888548f416d28ea9c990aa9a3bd0ab6ac16715e3f6b3fd6",
-  "ed25519_seed": "0xa29ec2ea2bcdb9db24af6fb04855c1041d9708400a06c1859a026fbeb5391593",
-  "ed25519_public_key": "0x8df25ef87e99177799296d8bfa7ed2397a5f6d96140c77dcc4f55e55711045fe",
-  "ed25519_signature": "0xff152514f51af2815bf9d89bffa66c71e97f865b93a312d371aded36a3a433158e159a239b688e23ca872386d1fdfe6f16377e97644dbda10b5ec802268e3409"
+  "value": "250000000",
+  "verifying_contract": "0x2e234DAe75C793f67A35089C9d99245E1C58470b"
 }
``````


### Task 3: The DEX venue on `SCaaSDex` (`TradeOrder` / `DexOrder`, `mtxSettle` settlements, cancels where the order lives), order entry jobs

The venue speaks to the `SCaaSDex` clone (NODE-DEX-15/16, N7–N9). `abi.rs` gains `Leg`, `DexOrder`, `Settlement`,
`CancelOrder`, `InvalidateNonces` and `ISCaaSDex` (settle, `settleOne`, cancels, digests, `pulled`, `minNonce`,
`puller`, `marketListed`, `tokenKind`, events `LegSettled`/`MatchFailed`/`TradeFilled`/`OrderCancelled`/`NoncesInvalidated`,
errors). `dex.rs` is the settlement mirror and the book: `WireOrder` (the `TradeOrder` wire form), `MarketCfg`,
`Resting { hash, sell, order, sig, remaining, seq }`, `min_fill` (the 50 % effective floor), `maker_receives`
(`ceil(x·R/A)`), `limits_ok`/`settlement_ok`, `Book::admit` (flags `IOC | LISTED_POOLS` only, `ESCROW` refused, `dex`
= the venue's DEX, `relayer` = the lane, fee ≤ 1 %, fee rate by role, committed balance), matching (one
`PlannedSettlement` per taker; self, cheap and dust makers skipped; a maker below its minimum skipped for a deeper one;
the taker settles iff it takes its minimum or closes; a crossing remainder dropped), `restore`, `drop_below`, depth.
`dex/venue.rs`: kinds and the puller from the DEX, order hashes from the token or DEX views, on-chain state (`pulled`,
`minNonce`, balance, allowance to the puller), simulation of the whole `mtxSettle` with the `SigCheckGasStarved` split,
attribution through `settleOne` revert data, the place loop (≤ 3 rounds), trades per settlement, cancel and cancel-all
(no job when the invalidation already holds, N6), `sync_once` (makers restored first), `watch_once` on the DEX and the
market tokens (`MatchFailed` with an empty reason = `out_of_gas`). The gateway's order bodies name `sellToken`; Odoo
jobs carry the entry fields; the submitter encodes `mtxCancelOrder`, `mtxInvalidateNonces`, `mtxWrap` entry jobs, pinned
by the KAT calldata. The e2e DEX test runs on the deploy's two demo tokens, a `createDex` clone, an outside `MockERC20`
through the puller.

**Files:** modify `scaas-node/src/{abi,dex,gateway,odoo,submit}.rs`, `scaas-node/src/dex/venue.rs`,
`scaas-node/tests/{e2e,fuzz}.rs`.

- [ ] **Step 1: Apply the diff below.**
- [ ] **Step 2: Gates** (a full `forge build` first; the e2e reads `out/Mocks.sol/MockERC20.json`): `cargo test --lib`
  246 passed; `cargo test --test mesh_vectors --test fuzz` 4 + 1 passed; clippy clean; e2e 4/4; e2e_hedera 1/1.
- [ ] **Step 3: Commit** `P5 T3: DEX venue on SCaaSDex (TradeOrder/DexOrder, mtxSettle settlements, token and DEX cancels), order entry jobs`.

``````diff
diff --git a/scaas-node/src/abi.rs b/scaas-node/src/abi.rs
index d31682a..5439188 100644
--- a/scaas-node/src/abi.rs
+++ b/scaas-node/src/abi.rs
@@ -1,6 +1,9 @@
 //! ABI — copied from `smartcontracts/evm/src` (`IMetaTx`, `IERC20MetaTx`, `IERC20Payment`, `ITradeToken`, `MetaTxLib`,
-//! `MandateWallet`), never inferred: one wrong `indexed` is one wrong topic. Pinned by the forge KATs
-//! (`metatx_kat.json`, `metatransfer_kat.json`, `trade_kat.json`: digests and relayed calldata).
+//! `ISCaaSDex`, `MandateWallet`), never inferred: one wrong `indexed` is one wrong topic. Pinned by the forge KATs
+//! (`metatx_kat.json`, `metatransfer_kat.json`, `trade_kat.json`, `dex_order_kat.json`: digests and relayed calldata).
+// `sol!` builds a constructor per event; `LegSettled` has ten fields.
+#![allow(clippy::too_many_arguments)]
+
 use alloy::sol;
 use alloy::sol_types::SolInterface;
 
@@ -27,6 +30,59 @@ sol! {
         uint256 validUntil;
     }
 
+    /// `ISCaaSDex.Leg`: one order in one settlement; `fill` = its sell fill in this call.
+    #[derive(Debug, PartialEq, Eq)]
+    struct Leg { address sellToken; TradeOrder o; bytes sig; uint256 fill; }
+
+    /// An outside-token order (CTR-DEX-18): the `TradeOrder` signed in the DEX's domain with its sell token.
+    #[derive(Debug, PartialEq, Eq)]
+    struct DexOrder { address sellToken; TradeOrder order; }
+
+    /// One taker against one or more makers (CTR-DEX-16); `ref` is the submitter's (the venue's trade tag).
+    #[derive(Debug, PartialEq, Eq)]
+    struct Settlement { bytes32 ref; Leg taker; Leg[] makers; }
+
+    struct CancelOrder { bytes32 orderHash; }
+    struct InvalidateNonces { address from; uint256 batch; uint256 minNonce; }
+
+    /// `SCaaSDex` (a clone per DEX, `createDex`): what the venue sends and reads.
+    #[derive(Debug)]
+    interface ISCaaSDex {
+        function mtxSettle(Settlement[] s) external returns (bool[] ok);
+        function settleOne(Settlement s, address submitter) external;
+        function mtxCancelOrders(DexOrder[] orders, bytes[] sigs) external;
+        function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes sig) external;
+        function dexOrderDigest(address sellToken, TradeOrder o) external view returns (bytes32);
+        function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
+        function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
+        function pulled(bytes32 orderHash) external view returns (uint256);
+        function minNonce(address from, uint256 batch) external view returns (uint256);
+        function puller() external view returns (address);
+        function marketListed(address a, address b) external view returns (bool);
+        function tokenKind(address token) external view returns (uint8);
+        function chainUid() external view returns (bytes32);
+        event LegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
+            uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
+        event MatchFailed(bytes32 indexed ref, bytes reason);
+        event TradeFilled(bytes32 indexed orderHash, address indexed from, uint256 sellFill, uint256 receiveFill,
+            uint256 dexFee);
+        event OrderCancelled(bytes32 indexed orderHash, address indexed from);
+        event NoncesInvalidated(address indexed from, uint256 indexed batch, uint256 minNonce);
+        error NothingSettled();
+        error NoMakers();
+        error WrongRelayer(address submitter);
+        error DexMismatch(address dex);
+        error TokenMismatch();
+        error SelfTrade(address from);
+        error DuplicateOrder(bytes32 orderHash);
+        error MarketNotListed(address tokenA, address tokenB);
+        error BadSignature(bytes32 digest);
+        error LengthMismatch();
+        error FillMismatch(uint256 expected, uint256 got);
+        error ConservationBroken(address token);
+        error NotSelf();
+    }
+
     /// Every SCaaS contract on `MetaTxBase` (`IMetaTx`) plus the token surface the node reads or relays.
     #[derive(Debug)]
     interface IToken {
@@ -42,6 +98,8 @@ sol! {
         function transfer(address to, uint256 value) external returns (bool);
         function mtxCancelOrder(TradeOrder o, bytes sig) external;
         function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes sig) external;
+        function mtxWrap(address underlying, TradeOrder o, bytes sig) external;
+        function allowance(address owner, address spender) external view returns (uint256);
         function tradeOrderDigest(TradeOrder o) external view returns (bytes32);
         function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
         function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
@@ -113,6 +171,9 @@ pub fn decode_revert(data: &[u8]) -> String {
     if let Ok(e) = IToken::ITokenErrors::abi_decode(data) {
         return format!("{e:?}");
     }
+    if let Ok(e) = ISCaaSDex::ISCaaSDexErrors::abi_decode(data) {
+        return format!("{e:?}");
+    }
     if let Ok(e) = IMandateWallet::IMandateWalletErrors::abi_decode(data) {
         return format!("{e:?}");
     }
diff --git a/scaas-node/src/dex.rs b/scaas-node/src/dex.rs
index 1263642..1a1a539 100644
--- a/scaas-node/src/dex.rs
+++ b/scaas-node/src/dex.rs
@@ -1,175 +1,122 @@
-//! DEX sổ lệnh (R35, `2026-10-03-dex-design.md` §3): kiểu lệnh EIP-712 của `SCaaSDexV1`, sổ theo
-//! thị trường với ưu tiên giá-thời gian, khớp một phần / IOC / FOK, chặn spam. Phần này THUẦN (không
-//! I/O, test được từng bit); RPC, Odoo, gateway nằm ở `dex::venue`.
+//! DEX order book (NODE-DEX-01, NODE-DEX-15): role-free `TradeOrder`s settled by `SCaaSDex.mtxSettle`
+//! (contracts/dex.md), one book per market, price-time priority, partial fills, IOC, fill-or-kill (`minFill = amount`).
+//! An incoming order that crosses is the taker of ONE settlement against the resting orders it crosses (its makers);
+//! every order fills at least `max(minFill, ceil(amount / 2))` per settlement unless the fill closes it, exactly as the
+//! token (`TradeLib.record`) and the DEX (`settleOne`) check. PURE (no I/O, tested bit for bit); RPC, the client store
+//! and the gateway are in `dex::venue`.
 pub mod venue;
 
 use std::collections::HashMap;
 
 use alloy::primitives::{keccak256, Address, Bytes, B256, U256, U512};
-use alloy::sol;
 use alloy::sol_types::{Eip712Domain, SolStruct};
 use anyhow::{anyhow, bail, Result};
 use serde::{Deserialize, Serialize};
 
+pub use crate::abi::{CancelOrder, DexOrder, ISCaaSDex, InvalidateNonces, Leg, Settlement, TradeOrder};
 use crate::metatx::{addr, uint};
 
-sol! {
-    /// Phải khớp TỪNG KÝ TỰ với `SCaaSDexV1.ORDER_TYPEHASH` (khoá bằng `dex_kat.json`).
-    #[derive(Debug, PartialEq, Eq)]
-    struct Order {
-        address maker; address taker; address sellToken; address buyToken;
-        uint256 sellAmount; uint256 buyAmount; uint256 nonce; uint256 expiry;
-        uint32 maxFeePpm; uint8 flags; address relayer; uint8 feeMode; uint256 fee;
-        address feeToken; address feeRecipient;
-    }
-
-    struct CancelOrder { bytes32 orderHash; }
-    struct InvalidateNonces { address maker; uint256 minNonce; }
-
-    #[derive(Debug)]
-    struct Match {
-        bytes32 tag; Order maker; bytes makerSig; Order taker; bytes takerSig;
-        uint256 makerFill; uint256 takerFill;
-    }
-
-    #[derive(Debug)]
-    struct CancelReq { Order order; bytes sig; }
-
-    #[derive(Debug)]
-    struct Market { bool listed; bool feeOn; uint32 makerFeePpm; uint32 takerFeePpm; address feeRecipient; }
-
-    #[derive(Debug)]
-    struct Fill {
-        address sellToken; uint256 sold; address buyToken; uint256 received; uint256 dexFee;
-        address dexFeeRecipient; address relayerFeeToken; uint256 relayerFee; address relayerFeeRecipient;
-        uint256 filledTotal;
-    }
-
-    #[derive(Debug)]
-    interface ISCaaSDex {
-        function settle(Match[] ms) external returns (bool[] ok);
-        function cancel(CancelReq[] reqs) external;
-        function invalidateNonces(address maker, uint256 newMin, bytes sig) external;
-        function checkOrder(Order o, bytes sig) external view
-            returns (bytes32 h, uint8 status, uint256 remaining, uint256 fundable, uint256 feeFundable);
-        function markets(bytes32 key) external view
-            returns (bool listed, bool feeOn, uint32 makerFeePpm, uint32 takerFeePpm, address feeRecipient);
-        function marketKey(address a, address b) external pure returns (bytes32);
-        function minNonce(address maker) external view returns (uint256);
-        event OrderFilled(bytes32 indexed tag, bytes32 indexed orderHash, address indexed owner, Fill fill);
-        event Matched(bytes32 indexed tag, bytes32 indexed makerHash, bytes32 indexed takerHash);
-        event MatchFailed(bytes32 indexed tag, bytes reason);
-        event OrderCancelled(bytes32 indexed orderHash, address indexed maker);
-        event NoncesInvalidated(address indexed maker, uint256 minNonce);
-        error NothingSettled();
-        error Overfill(bytes32 orderHash, uint256 filledBefore, uint256 fill, uint256 sellAmount);
-        error PriceLimit(bytes32 orderHash);
-        error BadSignature(bytes32 orderHash);
-        error OrderExpired(bytes32 orderHash);
-        error NonceInvalidated(bytes32 orderHash);
-        error FillOrKill(bytes32 orderHash);
-        error FeeAboveSigned(bytes32 orderHash);
-        error NonceNotIncreasing();
-        error MarketNotListed();
-    }
-}
-
-pub const FLAG_FOK: u8 = 1;
-pub const FLAG_IOC: u8 = 2;
-/// `checkOrder` status `ST_OK`.
-pub const ST_OK: u8 = 0;
-/// Trần lệnh nghỉ toàn sổ — lệnh hợp lệ gần như miễn phí với người đặt (gasless).
+pub const FLAG_IOC: u8 = 1;
+/// Path B (escrow + refund): not built by this venue, refused at intake.
+pub const FLAG_ESCROW: u8 = 2;
+/// Read only on the exchange path (CTR-DEX-23); a book order may carry it.
+pub const FLAG_LISTED_POOLS: u8 = 4;
+/// `tokenKind`: 1 = SCaaS (the token checks the order), 2 = outside (a `DexOrder`, pulled through the `DexPuller`).
+pub const KIND_SCAAS: u8 = 1;
+pub const KIND_OUTSIDE: u8 = 2;
+/// Whole-book cap of resting orders: a valid order is almost free for its signer (gasless).
 pub const MAX_RESTING: usize = 10_000;
 pub const MAX_OPEN_PER_MAKER: usize = 50;
 pub const MIN_TTL_SECS: u64 = 5;
 pub const MAX_TTL_SECS: u64 = 30 * 86_400;
-const PPM: u64 = 1_000_000;
+/// `TradeLib.MAX_FEE_PPM`: an order signs at most 1 % DEX fee.
 const MAX_FEE_PPM: u64 = 10_000;
 
-pub fn domain(chain_id: u64, dex: Address) -> Eip712Domain {
+/// The salted EIP-712 domain of a SCaaS contract: `(name, "1", chainId, contract, chain_uid)`.
+pub fn domain(name: &str, chain_id: u64, contract: Address, chain_uid: B256) -> Eip712Domain {
     Eip712Domain::new(
-        Some("SCaaS Dex".into()),
+        Some(name.to_string().into()),
         Some("1".into()),
         Some(U256::from(chain_id)),
-        Some(dex),
-        None,
+        Some(contract),
+        Some(chain_uid),
     )
 }
 
-pub fn order_hash(d: &Eip712Domain, o: &Order) -> B256 {
-    o.eip712_signing_hash(d)
+/// A SCaaS sell token's order hash: the `TradeOrder` in the token's own domain (`tradeOrderDigest`).
+pub fn trade_order_hash(token_domain: &Eip712Domain, o: &TradeOrder) -> B256 {
+    o.eip712_signing_hash(token_domain)
+}
+
+/// An outside sell token's order hash: `DexOrder(sellToken, order)` in the DEX's domain (`dexOrderDigest`).
+pub fn dex_order_hash(dex_domain: &Eip712Domain, sell: Address, o: &TradeOrder) -> B256 {
+    DexOrder { sellToken: sell, order: o.clone() }.eip712_signing_hash(dex_domain)
 }
 
 pub fn cancel_digest(d: &Eip712Domain, h: B256) -> B256 {
     CancelOrder { orderHash: h }.eip712_signing_hash(d)
 }
 
-pub fn invalidate_digest(d: &Eip712Domain, maker: Address, min: U256) -> B256 {
-    InvalidateNonces { maker, minNonce: min }.eip712_signing_hash(d)
+pub fn invalidate_digest(d: &Eip712Domain, from: Address, batch: U256, min: U256) -> B256 {
+    InvalidateNonces { from, batch, minNonce: min }.eip712_signing_hash(d)
 }
 
 // ---------------------------------------------------------------------------------- wire
 
-/// Định dạng dây (chuỗi thập phân, như `WireMetaTx`): gateway nhận, Odoo lưu.
+/// `TradeOrder` on the wire (decimal strings, camelCase), as the gateway takes it and the client stores it.
 #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
-#[serde(rename_all = "camelCase")]
+#[serde(rename_all = "camelCase", deny_unknown_fields)]
 pub struct WireOrder {
-    pub maker: String,
-    pub taker: String,
-    pub sell_token: String,
-    pub buy_token: String,
-    pub sell_amount: String,
-    pub buy_amount: String,
-    pub nonce: String,
-    pub expiry: String,
-    pub max_fee_ppm: u32,
-    pub flags: u8,
-    pub relayer: String,
-    pub fee_mode: u8,
+    pub from: String,
+    pub receive_token: String,
+    pub amount: String,
+    pub receive_amount: String,
+    pub min_fill: String,
     pub fee: String,
-    pub fee_token: String,
-    pub fee_recipient: String,
+    pub relayer: String,
+    pub dex: String,
+    pub destination: String,
+    pub flags: u8,
+    pub batch: String,
+    pub nonce: String,
+    pub valid_until: String,
 }
 
 impl WireOrder {
-    pub fn to_sol(&self) -> Result<Order> {
-        Ok(Order {
-            maker: addr(&self.maker)?,
-            taker: addr(&self.taker)?,
-            sellToken: addr(&self.sell_token)?,
-            buyToken: addr(&self.buy_token)?,
-            sellAmount: uint(&self.sell_amount)?,
-            buyAmount: uint(&self.buy_amount)?,
-            nonce: uint(&self.nonce)?,
-            expiry: uint(&self.expiry)?,
-            maxFeePpm: self.max_fee_ppm,
-            flags: self.flags,
-            relayer: addr(&self.relayer)?,
-            feeMode: self.fee_mode,
+    pub fn to_sol(&self) -> Result<TradeOrder> {
+        Ok(TradeOrder {
+            from: addr(&self.from)?,
+            receiveToken: addr(&self.receive_token)?,
+            amount: uint(&self.amount)?,
+            receiveAmount: uint(&self.receive_amount)?,
+            minFill: uint(&self.min_fill)?,
             fee: uint(&self.fee)?,
-            feeToken: addr(&self.fee_token)?,
-            feeRecipient: addr(&self.fee_recipient)?,
+            relayer: addr(&self.relayer)?,
+            dex: addr(&self.dex)?,
+            destination: addr(&self.destination)?,
+            flags: self.flags,
+            batch: uint(&self.batch)?,
+            nonce: uint(&self.nonce)?,
+            validUntil: uint(&self.valid_until)?,
         })
     }
 
-    pub fn from_sol(o: &Order) -> Self {
+    pub fn from_sol(o: &TradeOrder) -> Self {
         let a = |x: Address| format!("{x:#x}");
         Self {
-            maker: a(o.maker),
-            taker: a(o.taker),
-            sell_token: a(o.sellToken),
-            buy_token: a(o.buyToken),
-            sell_amount: o.sellAmount.to_string(),
-            buy_amount: o.buyAmount.to_string(),
-            nonce: o.nonce.to_string(),
-            expiry: o.expiry.to_string(),
-            max_fee_ppm: o.maxFeePpm,
-            flags: o.flags,
-            relayer: a(o.relayer),
-            fee_mode: o.feeMode,
+            from: a(o.from),
+            receive_token: a(o.receiveToken),
+            amount: o.amount.to_string(),
+            receive_amount: o.receiveAmount.to_string(),
+            min_fill: o.minFill.to_string(),
             fee: o.fee.to_string(),
-            fee_token: a(o.feeToken),
-            fee_recipient: a(o.feeRecipient),
+            relayer: a(o.relayer),
+            dex: a(o.dex),
+            destination: a(o.destination),
+            flags: o.flags,
+            batch: o.batch.to_string(),
+            nonce: o.nonce.to_string(),
+            valid_until: o.validUntil.to_string(),
         }
     }
 }
@@ -184,7 +131,8 @@ pub fn hex_of(b: &[u8]) -> String {
 
 // ---------------------------------------------------------------------------------- markets
 
-/// Thị trường do Odoo cấu hình (`dex_markets`); node đối chiếu với `markets(key)` on-chain.
+/// A market as the client configures it (`dex_markets`): venue policy only. The DEX itself holds the listing
+/// (`marketListed`) and each token's kind; the fee is each order's signed rate (NODE-DEX-15).
 #[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
 pub struct MarketCfg {
     pub id: i64,
@@ -192,10 +140,11 @@ pub struct MarketCfg {
     pub quote: Address,
     pub base_decimals: u8,
     pub quote_decimals: u8,
-    pub fee_on: bool,
+    /// An order whose signed `fee` is below the rate of the role it would play is not matched in that role.
+    #[serde(default)]
     pub maker_fee_ppm: u32,
+    #[serde(default)]
     pub taker_fee_ppm: u32,
-    pub fee_recipient: Address,
     #[serde(default = "zero")]
     pub min_base_amount: String,
 }
@@ -210,26 +159,22 @@ pub fn pair(a: Address, b: Address) -> (Address, Address) {
 
 // ---------------------------------------------------------------------------------- book
 
-/// Một lệnh trong sổ. `remaining` tính theo `sellToken`, đã trừ mọi cặp đang chờ settle.
+/// One order in the book. `remaining` is in the sell token, net of every settlement planned and not yet failed.
 #[derive(Debug, Clone, PartialEq)]
 pub struct Resting {
     pub hash: B256,
-    pub order: Order,
+    pub sell: Address,
+    pub order: TradeOrder,
     pub sig: Bytes,
     pub remaining: U256,
     pub seq: u64,
 }
 
-impl Resting {
-    fn filled(&self) -> U256 {
-        self.order.sellAmount - self.remaining
-    }
-}
-
-/// Hàng lưu ở Odoo (`blockchain.dex.order`): đủ để dựng lại sổ đúng thứ tự.
+/// The row the client stores (`blockchain.dex.order`): enough to rebuild the book in order.
 #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
 pub struct Row {
     pub order_hash: String,
+    pub sell_token: String,
     pub order: WireOrder,
     pub signature: String,
     pub remaining: String,
@@ -240,6 +185,7 @@ impl Row {
     pub fn of(r: &Resting) -> Self {
         Self {
             order_hash: format!("{:#x}", r.hash),
+            sell_token: format!("{:#x}", r.sell),
             order: WireOrder::from_sol(&r.order),
             signature: hex_of(&r.sig),
             remaining: r.remaining.to_string(),
@@ -250,6 +196,7 @@ impl Row {
     pub fn resting(&self) -> Result<Resting> {
         Ok(Resting {
             hash: self.order_hash.parse()?,
+            sell: addr(&self.sell_token)?,
             order: self.order.to_sol()?,
             sig: hex_bytes(&self.signature)?,
             remaining: uint(&self.remaining)?,
@@ -258,85 +205,79 @@ impl Row {
     }
 }
 
-/// Một cặp khớp chờ lên chain. `tag` là `Match.ref` on-chain — khoá trade ở Odoo.
+/// One settlement on its way to the chain: the taker (as it was before) sells `taker_fill` (= Σ makers' receive) and
+/// receives Σ maker sell fills. `tag` is `Settlement.ref` on chain and the trade's key in the client.
 #[derive(Debug, Clone, PartialEq)]
-pub struct PlannedFill {
+pub struct PlannedSettlement {
     pub tag: B256,
     pub market_id: i64,
-    pub maker: Resting,
     pub taker: Resting,
-    pub maker_fill: U256,
     pub taker_fill: U256,
+    /// `(maker as it was, its sell fill x, what it receives y = ceil(x · receiveAmount / amount))`.
+    pub makers: Vec<(Resting, U256, U256)>,
 }
 
-impl PlannedFill {
-    pub fn to_match(&self) -> Match {
-        Match {
-            tag: self.tag,
-            maker: self.maker.order.clone(),
-            makerSig: self.maker.sig.clone(),
-            taker: self.taker.order.clone(),
-            takerSig: self.taker.sig.clone(),
-            makerFill: self.maker_fill,
-            takerFill: self.taker_fill,
+impl PlannedSettlement {
+    pub fn to_settlement(&self) -> Settlement {
+        let leg = |r: &Resting, fill: U256| Leg { sellToken: r.sell, o: r.order.clone(), sig: r.sig.clone(), fill };
+        Settlement {
+            r#ref: self.tag,
+            taker: leg(&self.taker, self.taker_fill),
+            makers: self.makers.iter().map(|(m, x, _)| leg(m, *x)).collect(),
         }
     }
+
+    /// What the taker receives: the makers' sell fills.
+    pub fn taker_receives(&self) -> U256 {
+        self.makers.iter().map(|(_, x, _)| *x).sum()
+    }
+
+    pub fn valid_until(&self) -> U256 {
+        self.makers.iter().map(|(m, _, _)| m.order.validUntil).chain([self.taker.order.validUntil]).min().unwrap_or_default()
+    }
 }
 
 #[derive(Debug, Default, PartialEq)]
 pub struct Placement {
-    pub fills: Vec<PlannedFill>,
-    /// Phần còn lại vào sổ (GTC).
+    pub settlement: Option<PlannedSettlement>,
+    /// The remainder in the book (GTC, not crossing).
     pub rested: Option<Resting>,
-    /// Phần còn lại bị bỏ (IOC/FOK) — không bao giờ nghỉ.
+    /// The remainder cancelled: IOC, or a remainder that would rest crossed (it cannot meet a crossing order's
+    /// minimum fill, so it would sit there locked).
     pub dropped: U256,
-    /// `seq` (ưu tiên thời gian) cấp cho lệnh này, nghỉ hay không.
+    /// Makers taken off the book as dust (NODE-DEX-05): they cannot receive one unit for their remainder.
+    pub dust: Vec<Resting>,
+    /// Time priority given to this order, rested or not.
     pub seq: u64,
 }
 
 #[derive(Debug, Clone)]
 struct MarketBook {
     cfg: MarketCfg,
-    /// Lệnh bán base, tốt nhất trước.
+    /// Orders selling base, best first.
     asks: Vec<Resting>,
-    /// Lệnh bán quote, tốt nhất trước.
+    /// Orders selling quote, best first.
     bids: Vec<Resting>,
 }
 
 impl MarketBook {
-    fn side_mut(&mut self, sell_token: Address) -> &mut Vec<Resting> {
-        if sell_token == self.cfg.base { &mut self.asks } else { &mut self.bids }
+    fn side_mut(&mut self, sell: Address) -> &mut Vec<Resting> {
+        if sell == self.cfg.base { &mut self.asks } else { &mut self.bids }
     }
 }
 
-/// `a` chào giá tốt hơn `b` cho phía đối diện: đưa nhiều hơn trên mỗi đơn vị nhận
-/// (`a.sell/a.buy > b.sell/b.buy`), nhân chéo — lượng ở cửa `< 2^128` nên không tràn U512.
-fn better(a: &Order, b: &Order) -> bool {
-    mul(a.sellAmount, b.buyAmount) > mul(b.sellAmount, a.buyAmount)
+/// `a` offers the opposite side more per unit received than `b` (`a.amount / a.receiveAmount` larger), by
+/// cross-multiplication (amounts at intake `< 2^128`, so no U512 overflow).
+fn better(a: &TradeOrder, b: &TradeOrder) -> bool {
+    mul(a.amount, b.receiveAmount) > mul(b.amount, a.receiveAmount)
 }
 
 fn mul(a: U256, b: U256) -> U512 {
     U512::from(a) * U512::from(b)
 }
 
-fn crosses(rest: &Order, inc: &Order) -> bool {
-    mul(rest.buyAmount, inc.buyAmount) <= mul(inc.sellAmount, rest.sellAmount)
-}
-
-/// Bản sao đúng điều kiện của `SCaaSDexV1._checkMatch` + `_accept` cho lượng và giá: book không
-/// bao giờ phát một cặp contract sẽ từ chối (review D2).
-pub fn limits_ok(maker: &Resting, taker: &Resting, x: U256, y: U256) -> bool {
-    let (m, t) = (&maker.order, &taker.order);
-    let side_ok = |r: &Resting, fill: U256| {
-        let fok = r.order.flags & FLAG_FOK != 0;
-        fill <= r.remaining && (!fok || (r.filled().is_zero() && fill == r.order.sellAmount))
-    };
-    !x.is_zero()
-        && !y.is_zero()
-        && side_ok(maker, x)
-        && side_ok(taker, y)
-        && mul(y, m.sellAmount) >= mul(x, m.buyAmount)
-        && mul(x, t.sellAmount) >= mul(y, t.buyAmount)
+fn crosses(rest: &TradeOrder, inc: &TradeOrder) -> bool {
+    mul(rest.receiveAmount, inc.receiveAmount) <= mul(inc.amount, rest.amount)
 }
 
 fn div_ceil(a: U512, b: U512) -> U512 {
@@ -347,23 +288,60 @@ fn to256(v: U512) -> U256 {
     U256::from_limbs_slice(&v.as_limbs()[..4])
 }
 
-/// Phí relayer của `o` cho lượng `sold` — đúng như `SCaaSDexV1._relayerFee`. `(token, amount)`.
-pub fn relayer_fee(o: &Order, sold: U256) -> (Address, U256) {
-    let token = if o.feeToken == Address::ZERO { o.sellToken } else { o.feeToken };
-    match o.feeMode {
-        1 => (token, sold * o.fee / U256::from(PPM)),
-        2 if !o.sellAmount.is_zero() => (token, to256(mul(o.fee, sold) / U512::from(o.sellAmount))),
-        _ => (token, U256::ZERO),
-    }
+/// The effective minimum sell fill per settlement: `max(minFill, ceil(amount / 2))` (`TradeLib.record`).
+pub fn min_fill(o: &TradeOrder) -> U256 {
+    o.minFill.max(o.amount - o.amount / U256::from(2u8))
 }
 
-/// Tag duy nhất cho một cặp. Hai lệnh + lượng đã khớp KHÔNG đủ: một cặp fail rồi được trả về sổ
-/// khớp lại đúng như cũ, và Odoo coi tag trùng là phát lại. Muối ngẫu nhiên mỗi tiến trình + bộ đếm.
-fn tag(maker: &Resting, taker: &Resting, salt: u64, n: u64) -> B256 {
-    let mut b = Vec::with_capacity(112);
-    b.extend_from_slice(maker.hash.as_slice());
+/// What a maker receives for selling `x` at its own price: `ceil(x · receiveAmount / amount)` (`SCaaSDex._makerCalc`).
+pub fn maker_receives(o: &TradeOrder, x: U256) -> U256 {
+    to256(div_ceil(mul(x, o.receiveAmount), U512::from(o.amount)))
+}
+
+/// One maker against the taker for `x` (maker sells) and `y` (taker sells) at the maker's price, exactly as the
+/// token and the DEX check it: in the remainders, `y` is the maker's receive, both price limits hold.
+pub fn limits_ok(maker: &Resting, taker: &Resting, x: U256, y: U256) -> bool {
+    let (m, t) = (&maker.order, &taker.order);
+    !x.is_zero()
+        && !y.is_zero()
+        && x <= maker.remaining
+        && y <= taker.remaining
+        && y == maker_receives(m, x)
+        && mul(y, m.amount) >= mul(x, m.receiveAmount)
+        && mul(x, t.amount) >= mul(y, t.receiveAmount)
+}
+
+/// The whole settlement as the chain checks it (a mirror for tests and the venue's last guard): every maker leg in
+/// limits and at least its minimum unless it closes, the taker's fill = Σ makers' receive and at least its minimum
+/// unless it closes, no self-trade, no duplicate maker, makers on the taker's opposite side.
+pub fn settlement_ok(s: &PlannedSettlement) -> bool {
+    let t = &s.taker;
+    let mut seen = Vec::new();
+    let legs_ok = s.makers.iter().all(|(m, x, y)| {
+        let fresh = !seen.contains(&m.hash);
+        seen.push(m.hash);
+        fresh
+            && m.order.from != t.order.from
+            && m.sell == t.order.receiveToken
+            && m.order.receiveToken == t.sell
+            && limits_ok(m, t, *x, *y)
+            && (*x >= min_fill(&m.order) || *x == m.remaining)
+    });
+    let sum: U256 = s.makers.iter().map(|(_, _, y)| *y).sum();
+    legs_ok
+        && !s.makers.is_empty()
+        && s.taker_fill == sum
+        && sum <= t.remaining
+        && (sum >= min_fill(&t.order) || sum == t.remaining)
+        && mul(s.taker_receives(), t.order.amount) >= mul(sum, t.order.receiveAmount)
+}
+
+/// A unique tag per settlement. The orders and fills alone are not enough: a failed settlement handed back to the
+/// book re-matches exactly as before, and the client treats a repeated tag as a replay. Per-process salt + counter.
+fn tag(taker: &Resting, salt: u64, n: u64) -> B256 {
+    let mut b = Vec::with_capacity(80);
     b.extend_from_slice(taker.hash.as_slice());
-    b.extend_from_slice(&maker.filled().to_be_bytes::<32>());
+    b.extend_from_slice(&taker.remaining.to_be_bytes::<32>());
     b.extend_from_slice(&salt.to_be_bytes());
     b.extend_from_slice(&n.to_be_bytes());
     keccak256(b)
@@ -379,7 +357,7 @@ pub struct Book {
     markets: HashMap<(Address, Address), MarketBook>,
     next_seq: u64,
     salt: u64,
-    fills_made: u64,
+    made: u64,
 }
 
 impl Book {
@@ -388,17 +366,17 @@ impl Book {
             .into_iter()
             .map(|cfg| (pair(cfg.base, cfg.quote), MarketBook { cfg, asks: vec![], bids: vec![] }))
             .collect();
-        Self { markets, next_seq: 1, salt: random_u64(), fills_made: 0 }
+        Self { markets, next_seq: 1, salt: random_u64(), made: 0 }
     }
 
-    /// Dựng lại từ hàng Odoo: chèn theo `seq` tăng nên cùng giá vẫn giữ thứ tự thời gian.
+    /// Rebuild from the client's rows: inserted by increasing `seq`, so equal prices keep their time order.
     pub fn load(markets: Vec<MarketCfg>, rows: &[Row]) -> Result<Self> {
         let mut book = Self::new(markets);
         let mut rs = rows.iter().map(Row::resting).collect::<Result<Vec<_>>>()?;
         rs.sort_by_key(|r| r.seq);
         for r in rs {
             book.next_seq = book.next_seq.max(r.seq + 1);
-            if book.market(&r.order).is_some() {
+            if book.market_of(r.sell, r.order.receiveToken).is_some() {
                 book.insert(r);
             }
         }
@@ -415,8 +393,8 @@ impl Book {
         self.markets.values().map(|m| &m.cfg)
     }
 
-    pub fn market(&self, o: &Order) -> Option<&MarketCfg> {
-        self.markets.get(&pair(o.sellToken, o.buyToken)).map(|m| &m.cfg)
+    pub fn market_of(&self, sell: Address, receive: Address) -> Option<&MarketCfg> {
+        self.markets.get(&pair(sell, receive)).map(|m| &m.cfg)
     }
 
     pub fn market_by_id(&self, id: i64) -> Option<&MarketCfg> {
@@ -439,34 +417,23 @@ impl Book {
         self.all().find(|r| r.hash == h)
     }
 
-    pub fn open_of(&self, maker: Address) -> Vec<&Resting> {
-        let mut v: Vec<&Resting> = self.all().filter(|r| r.order.maker == maker).collect();
+    pub fn open_of(&self, from: Address) -> Vec<&Resting> {
+        let mut v: Vec<&Resting> = self.all().filter(|r| r.order.from == from).collect();
         v.sort_by_key(|r| r.seq);
         v
     }
 
-    /// Σ lượng `token` mà các lệnh mở của `maker` có thể kéo: phần bán còn lại + phí relayer còn lại.
-    pub fn committed(&self, maker: Address, token: Address) -> U256 {
-        self.all().filter(|r| r.order.maker == maker).fold(U256::ZERO, |acc, r| {
-            let mut c = acc;
-            if r.order.sellToken == token {
-                c += r.remaining;
-            }
-            let (ft, fee) = relayer_fee(&r.order, r.remaining);
-            if ft == token {
-                c += fee;
-            }
-            c
-        })
+    /// Σ of `sell` the open orders of `from` can still pull (NODE-DEX-07; the fee is on the received side).
+    pub fn committed(&self, from: Address, sell: Address) -> U256 {
+        self.all().filter(|r| r.order.from == from && r.sell == sell).map(|r| r.remaining).sum()
     }
 
-    /// Chèn theo (giá tốt nhất, `seq`). Lệnh cùng hash đã có ⇒ cộng `remaining` (trả lại phần
-    /// của một cặp fail).
+    /// Insert by (best price, `seq`). The same hash already there ⇒ add `remaining` (a failed fill handed back).
     fn insert(&mut self, r: Resting) {
-        let Some(mb) = self.markets.get_mut(&pair(r.order.sellToken, r.order.buyToken)) else { return };
-        let side = mb.side_mut(r.order.sellToken);
+        let Some(mb) = self.markets.get_mut(&pair(r.sell, r.order.receiveToken)) else { return };
+        let side = mb.side_mut(r.sell);
         if let Some(e) = side.iter_mut().find(|e| e.hash == r.hash) {
-            e.remaining = (e.remaining + r.remaining).min(e.order.sellAmount);
+            e.remaining = (e.remaining + r.remaining).min(e.order.amount);
             return;
         }
         let at = side
@@ -487,25 +454,25 @@ impl Book {
         None
     }
 
-    /// Trả `fill` về một lệnh sau khi cặp của nó fail on-chain (§2 bước 3), giữ `seq` cũ. Đi lại
-    /// qua matcher, không chèn thẳng: nếu cả hai bên cùng được trả thì chèn thẳng để lại một sổ
-    /// chéo (bid >= ask nằm yên). IOC/FOK không bao giờ nghỉ nên không bao giờ được trả (review D5).
+    /// Hand `fill` back to an order after its settlement failed on chain, keeping its `seq`. Through the matcher, not
+    /// straight in: when both sides come back, a straight insert would leave a crossed book. IOC never rests, so it is
+    /// never handed back.
     pub fn restore(&mut self, r: Resting, fill: U256) -> Placement {
-        if r.order.flags & (FLAG_IOC | FLAG_FOK) != 0 {
+        if r.order.flags & FLAG_IOC != 0 {
             return Placement { dropped: fill, seq: r.seq, ..Default::default() };
         }
         let current = self.remove(r.hash).map(|x| x.remaining).unwrap_or_default();
-        let remaining = (current + fill).min(r.order.sellAmount);
+        let remaining = (current + fill).min(r.order.amount);
         self.matching(Resting { remaining, ..r })
     }
 
-    /// Bỏ lệnh hết hạn; trả hash đã bỏ.
+    /// Drop expired orders; returns their hashes.
     pub fn purge(&mut self, now: u64) -> Vec<B256> {
         let mut gone = vec![];
         for mb in self.markets.values_mut() {
             for side in [&mut mb.asks, &mut mb.bids] {
                 side.retain(|r| {
-                    let live = r.order.expiry >= U256::from(now);
+                    let live = r.order.validUntil >= U256::from(now);
                     if !live {
                         gone.push(r.hash);
                     }
@@ -516,157 +483,187 @@ impl Book {
         gone
     }
 
-    /// Bỏ mọi lệnh của `maker` có `nonce < min` (huỷ-hết on-chain).
-    pub fn drop_below(&mut self, maker: Address, min: U256) -> Vec<B256> {
-        let hs: Vec<B256> =
-            self.all().filter(|r| r.order.maker == maker && r.order.nonce < min).map(|r| r.hash).collect();
-        for h in &hs {
-            self.remove(*h);
-        }
-        hs
+    /// Drop the orders an `InvalidateNonces(from, batch, min)` closed: `from`'s orders on that lane with `nonce < min`,
+    /// selling one of `sells` (the token's own orders, or every outside token for the DEX's lane).
+    pub fn drop_below(&mut self, from: Address, batch: U256, min: U256, sells: &dyn Fn(Address) -> bool) -> Vec<Resting> {
+        let hs: Vec<B256> = self
+            .all()
+            .filter(|r| r.order.from == from && r.order.batch == batch && r.order.nonce < min && sells(r.sell))
+            .map(|r| r.hash)
+            .collect();
+        hs.iter().filter_map(|h| self.remove(*h)).collect()
     }
 
-    /// Kiểm cửa thuần (§3.4). `remaining` = phần còn lại on-chain; `fundable`/`fee_fundable` từ
-    /// `checkOrder`. Không đổi sổ.
+    /// Pure intake checks (NODE-DEX-15, intake section). `remaining` = `amount − pulled` on chain, `fundable` = the
+    /// balance (outside token: `min(balance, allowance to the puller)`). The book is unchanged.
     #[allow(clippy::too_many_arguments)]
     pub fn admit(
         &self,
         hash: B256,
-        o: &Order,
+        sell: Address,
+        o: &TradeOrder,
         remaining: U256,
         fundable: U256,
-        fee_fundable: U256,
         relayer: Address,
+        dex: Address,
         now: u64,
     ) -> Result<()> {
         let cap = U256::from(1u8) << 128;
-        if o.sellAmount.is_zero() || o.buyAmount.is_zero() || o.sellAmount >= cap || o.buyAmount >= cap {
+        if o.amount.is_zero() || o.receiveAmount.is_zero() || o.amount >= cap || o.receiveAmount >= cap {
             bail!("amounts must be in (0, 2^128)");
         }
-        if o.expiry <= U256::from(now + MIN_TTL_SECS) || o.expiry > U256::from(now + MAX_TTL_SECS) {
-            bail!("expiry must be within ({MIN_TTL_SECS} s, {MAX_TTL_SECS} s] from now");
+        if o.validUntil <= U256::from(now + MIN_TTL_SECS) || o.validUntil > U256::from(now + MAX_TTL_SECS) {
+            bail!("validUntil must be within ({MIN_TTL_SECS} s, {MAX_TTL_SECS} s] from now");
+        }
+        if o.flags & !(FLAG_IOC | FLAG_LISTED_POOLS) != 0 {
+            bail!("unknown flags, or ESCROW (Path B is not served by this venue)");
         }
-        if o.flags > FLAG_IOC || o.flags == FLAG_FOK | FLAG_IOC {
-            bail!("unknown or conflicting flags");
+        if o.minFill > o.amount {
+            bail!("minFill above amount");
+        }
+        // NODE-DEX-16: only the DEX this venue runs; home-bound (RS5-9): only this relayer settles a book order.
+        if o.dex != dex {
+            bail!("DEX_NOT_LISTED: order.dex must be {dex:#x}");
         }
-        // RS5-9: chỉ relayer này settle được lệnh trong sổ (chống MEV, chống settle lại phần đã huỷ).
         if o.relayer != relayer {
             bail!("order.relayer must be this relayer {relayer:#x}");
         }
-        if o.feeMode > 2 || (o.feeMode == 1 && U256::from(MAX_FEE_PPM) < o.fee) {
-            bail!("bad relayer fee");
+        if o.from == sell || o.dex == sell {
+            bail!("an order cannot sell its own signer or the DEX");
+        }
+        let Some(m) = self.market_of(sell, o.receiveToken) else { bail!("no market for this pair") };
+        if sell == o.receiveToken {
+            bail!("sell and receive token are the same");
         }
-        // Lệnh riêng tư hay trần phí dưới phí thị trường nằm trong sổ sẽ làm mọi cặp khớp với nó fail
-        // (review I2): sổ công khai chỉ nhận lệnh khớp được với bất kỳ ai, ở cả vai maker lẫn taker.
-        if o.taker != Address::ZERO {
-            bail!("order.taker must be zero on the public book");
+        if o.fee > U256::from(MAX_FEE_PPM) {
+            bail!("fee above 1 %");
         }
-        let Some(m) = self.market(o) else { bail!("no market for this pair") };
-        if m.fee_on && o.maxFeePpm < m.maker_fee_ppm.max(m.taker_fee_ppm) {
-            bail!("maxFeePpm below the market fee");
+        // A fee below a role's rate is never selected in that role (NODE-DEX-15): an IOC order only takes; a GTC order
+        // rests and makes, and takes when it crosses on arrival.
+        let rests = o.flags & FLAG_IOC == 0;
+        let (maker_ok, taker_ok) = (o.fee >= U256::from(m.maker_fee_ppm), o.fee >= U256::from(m.taker_fee_ppm));
+        let fee_ok = if rests { maker_ok && (taker_ok || !self.would_cross(sell, o)) } else { taker_ok };
+        if !fee_ok {
+            bail!("FEE_TOO_LOW: the signed fee is below the market's rate for the role this order would play");
         }
         let min = uint(&m.min_base_amount)?;
-        let base_amt = if o.sellToken == m.base { o.sellAmount } else { o.buyAmount };
+        let base_amt = if sell == m.base { o.amount } else { o.receiveAmount };
         if base_amt < min {
             bail!("below the market minimum {min}");
         }
         if remaining.is_zero() {
-            bail!("order is closed on-chain");
+            bail!("order is closed on chain");
         }
         if self.get(hash).is_some() {
             bail!("duplicate order");
         }
-        if self.open_of(o.maker).len() >= MAX_OPEN_PER_MAKER {
-            bail!("too many open orders for this maker");
+        if self.open_of(o.from).len() >= MAX_OPEN_PER_MAKER {
+            bail!("too many open orders for this signer");
         }
-        let rests = o.flags & (FLAG_IOC | FLAG_FOK) == 0;
         if rests && self.len() >= MAX_RESTING {
             bail!("order book full");
         }
-        // Cam kết cộng dồn (review D6): mọi lệnh mở của maker kéo cùng một số dư.
-        let (ft, fee) = relayer_fee(o, remaining);
-        let need_sell = self.committed(o.maker, o.sellToken) + remaining + if ft == o.sellToken { fee } else { U256::ZERO };
-        if need_sell > fundable {
-            bail!("balance/allowance {fundable} below what open orders commit ({need_sell})");
-        }
-        if ft != o.sellToken && !fee.is_zero() && self.committed(o.maker, ft) + fee > fee_fundable {
-            bail!("relayer-fee token balance/allowance too low");
+        // Committed balance (NODE-DEX-07): every open order of the signer pulls from the same balance.
+        let need = self.committed(o.from, sell) + remaining;
+        if need > fundable {
+            bail!("balance {fundable} below what open orders commit ({need})");
         }
         Ok(())
     }
 
-    /// Khớp `taker` (hash + `remaining` đã biết) vào sổ (§3.3). Đổi sổ: lệnh nghỉ giảm/biến mất,
-    /// phần còn lại GTC vào sổ. Gọi trên BẢN SAO khi cần thử trước.
-    pub fn place(&mut self, hash: B256, order: Order, sig: Bytes, remaining: U256) -> Placement {
+    /// An order of another signer on the opposite side crosses `o` (it would take on arrival).
+    fn would_cross(&self, sell: Address, o: &TradeOrder) -> bool {
+        self.markets.get(&pair(sell, o.receiveToken)).is_some_and(|mb| {
+            let opposite = if sell == mb.cfg.base { &mb.bids } else { &mb.asks };
+            opposite.iter().any(|r| r.order.from != o.from && crosses(&r.order, o))
+        })
+    }
+
+    /// Match `taker` (hash and on-chain `remaining` known) into the book. Changes the book: resting makers shrink or
+    /// leave, a GTC remainder rests. Call it on a COPY to try first.
+    pub fn place(&mut self, hash: B256, sell: Address, order: TradeOrder, sig: Bytes, remaining: U256) -> Placement {
         let seq = self.next_seq;
         self.next_seq += 1;
-        self.matching(Resting { hash, order, sig, remaining, seq })
+        self.matching(Resting { hash, sell, order, sig, remaining, seq })
     }
 
     fn matching(&mut self, mut t: Resting) -> Placement {
         let mut out = Placement { seq: t.seq, ..Default::default() };
-        let Some(mb) = self.markets.get_mut(&pair(t.order.sellToken, t.order.buyToken)) else {
+        let Some(mb) = self.markets.get_mut(&pair(t.sell, t.order.receiveToken)) else {
             out.dropped = t.remaining;
             return out;
         };
-        let market_id = mb.cfg.id;
-        let opposite = if t.order.sellToken == mb.cfg.base { &mut mb.bids } else { &mut mb.asks };
-        let fok = t.order.flags & FLAG_FOK != 0;
-        // Phí thị trường có thể tăng sau khi lệnh vào sổ: không phát cặp contract sẽ `FeeAboveSigned`.
-        let (fee_on, maker_ppm, taker_ppm) = (mb.cfg.fee_on, mb.cfg.maker_fee_ppm, mb.cfg.taker_fee_ppm);
-        let taker_fee_ok = !fee_on || t.order.maxFeePpm >= taker_ppm;
-        let mut i = 0;
-        while taker_fee_ok && i < opposite.len() && !t.remaining.is_zero() {
-            let r = &opposite[i];
-            if !crosses(&r.order, &t.order) {
-                break; // sắp theo giá: sau đây chỉ tệ hơn
-            }
-            if r.order.maker == t.order.maker || (fee_on && r.order.maxFeePpm < maker_ppm) {
-                i += 1; // self-trade prevention (review D21) / trần phí đã ký dưới phí maker
-                continue;
-            }
-            let (rs, rb) = (U512::from(r.order.sellAmount), U512::from(r.order.buyAmount));
-            let (x, y) = if fok {
-                // FOK: taker giao trọn `y = sellAmount` trong MỘT cặp (RS5-4).
-                let y = t.remaining;
-                (to256(U512::from(y) * rs / rb), y)
-            } else {
-                let x = r.remaining.min(to256(U512::from(t.remaining) * rs / rb));
-                (x, to256(div_ceil(U512::from(x) * rb, rs)))
-            };
-            if !limits_ok(r, &t, x, y) {
-                if fok {
-                    i += 1; // lệnh nghỉ này không lấp trọn được; thử lệnh sau
+        let (market_id, maker_ppm, taker_ppm) = (mb.cfg.id, mb.cfg.maker_fee_ppm, mb.cfg.taker_fee_ppm);
+        let base = mb.cfg.base;
+        let opposite = if t.sell == base { &mut mb.bids } else { &mut mb.asks };
+        let mut makers: Vec<(Resting, U256, U256)> = vec![];
+        let mut taken = U256::ZERO;
+        let can_take = t.order.fee >= U256::from(taker_ppm);
+        if can_take {
+            for r in opposite.iter() {
+                if !crosses(&r.order, &t.order) {
+                    break; // sorted by price: only worse from here
+                }
+                // self-trade (the DEX refuses it) or a signed fee under the maker rate: never this maker
+                if r.order.from == t.order.from || r.order.fee < U256::from(maker_ppm) {
+                    continue;
+                }
+                if maker_receives(&r.order, r.remaining).is_zero() || mul(r.remaining, r.order.receiveAmount) < U512::from(r.order.amount) {
+                    out.dust.push(r.clone()); // NODE-DEX-05: cannot receive one unit for its whole remainder
                     continue;
                 }
-                break; // phần lẻ do làm tròn: nghỉ lại, không phát cặp contract sẽ từ chối
+                let left = t.remaining - taken;
+                let x = r.remaining.min(to256(mul(left, r.order.amount) / U512::from(r.order.receiveAmount)));
+                if x.is_zero() {
+                    break; // the taker's rest buys less than one unit here
+                }
+                let y = maker_receives(&r.order, x);
+                // the maker's minimum per settlement, unless this fill closes it; a deeper maker may still fit
+                if x < r.remaining && x < min_fill(&r.order) {
+                    continue;
+                }
+                if !limits_ok(r, &Resting { remaining: left, ..t.clone() }, x, y) {
+                    break; // rounding at tiny amounts: never a leg the contract would refuse
+                }
+                makers.push((r.clone(), x, y));
+                taken += y;
+                if x < r.remaining {
+                    break; // the taker is used up at this maker's price
+                }
             }
-            self.fills_made += 1;
-            let fill = PlannedFill {
-                tag: tag(r, &t, self.salt, self.fills_made),
-                market_id,
-                maker: r.clone(),
-                taker: t.clone(),
-                maker_fill: x,
-                taker_fill: y,
-            };
-            out.fills.push(fill);
-            t.remaining -= y;
-            let r = &mut opposite[i];
-            r.remaining -= x;
-            if r.remaining.is_zero() {
+        }
+        for d in &out.dust {
+            if let Some(i) = opposite.iter().position(|r| r.hash == d.hash) {
                 opposite.remove(i);
-            } else {
-                i += 1;
             }
-            if fok {
-                break;
+        }
+        let settles = !makers.is_empty() && (taken >= min_fill(&t.order) || taken == t.remaining);
+        if settles {
+            for (m, x, _) in &makers {
+                if let Some(i) = opposite.iter().position(|r| r.hash == m.hash) {
+                    opposite[i].remaining -= *x;
+                    if opposite[i].remaining.is_zero() {
+                        opposite.remove(i);
+                    }
+                }
             }
+            self.made += 1;
+            out.settlement = Some(PlannedSettlement {
+                tag: tag(&t, self.salt, self.made),
+                market_id,
+                taker: t.clone(),
+                taker_fill: taken,
+                makers,
+            });
+            t.remaining -= taken;
         }
         if t.remaining.is_zero() {
             return out;
         }
-        if t.order.flags & (FLAG_IOC | FLAG_FOK) != 0 {
+        // A remainder that still crosses could not meet a crossing order's minimum fill: it would sit there locked, so
+        // it is cancelled. One that may not take (a fee under the taker rate, only on a hand-back) rests.
+        let crossed = can_take && opposite.iter().any(|r| r.order.from != t.order.from && crosses(&r.order, &t.order));
+        if t.order.flags & FLAG_IOC != 0 || crossed {
             out.dropped = t.remaining;
             return out;
         }
@@ -675,7 +672,7 @@ impl Book {
         out
     }
 
-    /// Mức giá gộp: `(bids, asks)`, mỗi mức `(giá thập phân, lượng base)`.
+    /// Aggregated levels `(bids, asks)`, each `(decimal price quote/base, base amount)`.
     pub fn depth(&self, market_id: i64, levels: usize) -> Option<(Vec<Level>, Vec<Level>)> {
         let mb = self.markets.values().find(|m| m.cfg.id == market_id)?;
         let cfg = &mb.cfg;
@@ -683,15 +680,15 @@ impl Book {
             let mut out: Vec<Level> = vec![];
             for r in side {
                 let (base_amt, quote_amt) = if is_ask {
-                    (r.order.sellAmount, r.order.buyAmount)
+                    (r.order.amount, r.order.receiveAmount)
                 } else {
-                    (r.order.buyAmount, r.order.sellAmount)
+                    (r.order.receiveAmount, r.order.amount)
                 };
                 let price = price_str(quote_amt, base_amt, cfg.base_decimals, cfg.quote_decimals);
                 let base_rem = if is_ask {
                     r.remaining
                 } else {
-                    to256(mul(r.remaining, r.order.buyAmount) / U512::from(r.order.sellAmount))
+                    to256(mul(r.remaining, r.order.receiveAmount) / U512::from(r.order.amount))
                 };
                 if let Some(l) = out.last_mut().filter(|l| l.price == price) {
                     l.base_amount += base_rem;
@@ -715,7 +712,7 @@ pub struct Level {
     pub orders: u32,
 }
 
-/// `quote/base` theo đơn vị hiển thị, 18 chữ số lẻ (review D16): không bao giờ chia nguyên thô.
+/// `quote/base` in display units, 18 decimals (review D16): never a raw integer division.
 pub fn price_str(quote: U256, base: U256, base_dec: u8, quote_dec: u8) -> String {
     if base.is_zero() {
         return "0".into();
@@ -733,98 +730,111 @@ pub fn price_str(quote: U256, base: U256, base_dec: u8, quote_dec: u8) -> String
 #[cfg(test)]
 mod tests {
     use super::*;
+    use alloy::sol_types::{SolCall, SolValue};
     use std::str::FromStr;
 
     const BASE: Address = Address::repeat_byte(0xaa);
     const QUOTE: Address = Address::repeat_byte(0xbb);
     const RELAYER: Address = Address::repeat_byte(0xee);
+    const DEX: Address = Address::repeat_byte(0xd0);
     const NOW: u64 = 1_800_000_000;
 
     fn market() -> MarketCfg {
-        MarketCfg {
-            id: 1,
-            base: BASE,
-            quote: QUOTE,
-            base_decimals: 18,
-            quote_decimals: 6,
-            fee_on: false,
-            maker_fee_ppm: 0,
-            taker_fee_ppm: 0,
-            fee_recipient: Address::ZERO,
-            min_base_amount: "0".into(),
-        }
+        MarketCfg { id: 1, base: BASE, quote: QUOTE, base_decimals: 18, quote_decimals: 6, maker_fee_ppm: 0,
+                    taker_fee_ppm: 0, min_base_amount: "0".into() }
     }
 
-    fn o(maker: u8, sell: Address, sell_amt: u64, buy: Address, buy_amt: u64, nonce: u64) -> Order {
-        Order {
-            maker: Address::repeat_byte(maker),
-            taker: Address::ZERO,
-            sellToken: sell,
-            buyToken: buy,
-            sellAmount: U256::from(sell_amt),
-            buyAmount: U256::from(buy_amt),
-            nonce: U256::from(nonce),
-            expiry: U256::from(NOW + 300),
-            maxFeePpm: 0,
-            flags: 0,
-            relayer: RELAYER,
-            feeMode: 0,
+    fn o(from: u8, receive: Address, amount: u64, receive_amount: u64, nonce: u64) -> TradeOrder {
+        TradeOrder {
+            from: Address::repeat_byte(from),
+            receiveToken: receive,
+            amount: U256::from(amount),
+            receiveAmount: U256::from(receive_amount),
+            minFill: U256::ZERO,
             fee: U256::ZERO,
-            feeToken: Address::ZERO,
-            feeRecipient: Address::ZERO,
+            relayer: RELAYER,
+            dex: DEX,
+            destination: Address::ZERO,
+            flags: 0,
+            batch: U256::from(1),
+            nonce: U256::from(nonce),
+            validUntil: U256::from(NOW + 300),
         }
     }
 
-    fn hash_of(o: &Order) -> B256 {
+    fn hash_of(o: &TradeOrder) -> B256 {
         keccak256(format!("{o:?}"))
     }
 
-    fn put(book: &mut Book, o: Order) -> Placement {
-        let h = hash_of(&o);
-        let rem = o.sellAmount;
-        book.place(h, o, Bytes::new(), rem)
+    fn sell_of(o: &TradeOrder) -> Address {
+        if o.receiveToken == QUOTE { BASE } else { QUOTE }
+    }
+
+    fn put(book: &mut Book, o: TradeOrder) -> Placement {
+        let rem = o.amount;
+        book.place(hash_of(&o), sell_of(&o), o, Bytes::new(), rem)
     }
 
-    fn ask(maker: u8, base: u64, quote: u64, nonce: u64) -> Order {
-        o(maker, BASE, base, QUOTE, quote, nonce)
+    /// Sells `base` base for at least `quote` quote.
+    fn ask(from: u8, base: u64, quote: u64, nonce: u64) -> TradeOrder {
+        o(from, QUOTE, base, quote, nonce)
     }
 
-    fn bid(maker: u8, quote: u64, base: u64, nonce: u64) -> Order {
-        o(maker, QUOTE, quote, BASE, base, nonce)
+    /// Sells `quote` quote for at least `base` base.
+    fn bid(from: u8, quote: u64, base: u64, nonce: u64) -> TradeOrder {
+        o(from, BASE, quote, base, nonce)
     }
 
+    fn makers(p: &Placement) -> Vec<(Address, U256, U256)> {
+        p.settlement.as_ref().map_or(vec![], |s| s.makers.iter().map(|(m, x, y)| (m.order.from, *x, *y)).collect())
+    }
+
+    fn word(k: &serde_json::Value, f: &str) -> String {
+        k[f].as_str().unwrap().to_string()
+    }
+
+    /// Byte-identical with forge (`DexKat.t.sol`, `TradeKat.t.sol`): the `DexOrder` hash in the DEX's salted domain,
+    /// the SCaaS taker's `TradeOrder` hash in its token's domain, the DEX cancel and invalidate digests, and the
+    /// `mtxSettle` / `mtxCancelOrders` / `mtxInvalidateNonces` calldata the venue sends.
     #[test]
-    fn kat_hashes_match_forge() {
-        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/dex_kat.json");
+    fn kat_hashes_and_calldata_match_forge() {
+        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/dex_order_kat.json");
         let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
-        let s = |f: &str| k[f].as_str().unwrap().to_string();
-        let a = |f: &str| Address::from_str(&s(f)).unwrap();
-        let u = |f: &str| U256::from_str(&s(f)).unwrap();
-        let order = Order {
-            maker: a("maker"),
-            taker: Address::ZERO,
-            sellToken: a("sell_token"),
-            buyToken: a("buy_token"),
-            sellAmount: u("sell_amount"),
-            buyAmount: u("buy_amount"),
-            nonce: u("nonce"),
-            expiry: u("expiry"),
-            maxFeePpm: s("max_fee_ppm").parse().unwrap(),
-            flags: s("flags").parse().unwrap(),
-            relayer: a("relayer"),
-            feeMode: s("fee_mode").parse().unwrap(),
-            fee: u("fee"),
-            feeToken: Address::ZERO,
-            feeRecipient: Address::ZERO,
-        };
-        let d = domain(s("chain_id").parse().unwrap(), a("dex"));
-        let h = order_hash(&d, &order);
-        assert_eq!(format!("{h:#x}"), s("order_hash").to_lowercase());
-        assert_eq!(format!("{:#x}", cancel_digest(&d, h)), s("cancel_digest").to_lowercase());
-        assert_eq!(
-            format!("{:#x}", invalidate_digest(&d, order.maker, U256::from(42))),
-            s("invalidate_digest").to_lowercase()
-        );
+        let a = |f: &str| Address::from_str(&word(&k, f)).unwrap();
+        let uid = B256::from_str(&word(&k, "salt")).unwrap();
+        let maker = TradeOrder::abi_decode(&hex_bytes(&word(&k, "maker_order_abi")).unwrap()).unwrap();
+        let taker = TradeOrder::abi_decode(&hex_bytes(&word(&k, "taker_order_abi")).unwrap()).unwrap();
+        let dd = domain("SCaaS Dex", 7622, a("dex"), uid);
+        let hm = dex_order_hash(&dd, a("outside_token"), &maker);
+        assert_eq!(format!("{hm:#x}"), word(&k, "dex_order_hash"));
+        let td = domain("SCaaS MetaToken", 7622, a("token"), uid);
+        assert_eq!(format!("{:#x}", trade_order_hash(&td, &taker)), word(&k, "taker_order_hash"));
+        assert_eq!(format!("{:#x}", cancel_digest(&dd, hm)), word(&k, "cancel_digest"));
+        assert_eq!(format!("{:#x}", invalidate_digest(&dd, maker.from, U256::from(1), U256::from(5))),
+            word(&k, "invalidate_digest"));
+        // the calldata: decode forge's, re-encode it here, byte for byte
+        let settle = hex_bytes(&word(&k, "settle_calldata")).unwrap();
+        let c = ISCaaSDex::mtxSettleCall::abi_decode(&settle).unwrap();
+        assert_eq!(c.s[0].makers[0].o, maker);
+        assert_eq!(c.s[0].taker.o, taker);
+        assert_eq!(ISCaaSDex::mtxSettleCall { s: c.s.clone() }.abi_encode(), settle.to_vec());
+        let cancel = hex_bytes(&word(&k, "cancel_orders_calldata")).unwrap();
+        let c = ISCaaSDex::mtxCancelOrdersCall::abi_decode(&cancel).unwrap();
+        assert_eq!((c.orders[0].sellToken, &c.orders[0].order), (a("outside_token"), &maker));
+        assert_eq!(ISCaaSDex::mtxCancelOrdersCall { orders: c.orders, sigs: c.sigs }.abi_encode(), cancel.to_vec());
+        let inv = hex_bytes(&word(&k, "invalidate_calldata")).unwrap();
+        let c = ISCaaSDex::mtxInvalidateNoncesCall::abi_decode(&inv).unwrap();
+        assert_eq!((c.from, c.batch, c.newMin), (maker.from, U256::from(1), U256::from(5)));
+        // the token-side order hash and cancel of trade_kat.json
+        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/trade_kat.json");
+        let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
+        let o = TradeOrder::abi_decode(&hex_bytes(&word(&k, "order_abi")).unwrap()).unwrap();
+        let td = domain("SCaaS MetaToken", 7622, Address::from_str(&word(&k, "verifying_contract")).unwrap(),
+            B256::from_str(&word(&k, "salt")).unwrap());
+        let h = trade_order_hash(&td, &o);
+        assert_eq!(format!("{h:#x}"), word(&k, "order_hash"));
+        assert_eq!(format!("{:#x}", cancel_digest(&td, h)), word(&k, "cancel_digest"));
+        assert_eq!(format!("{:#x}", invalidate_digest(&td, o.from, U256::from(7), U256::from(43))), word(&k, "invalidate_digest"));
     }
 
     #[test]
@@ -832,8 +842,11 @@ mod tests {
         let x = ask(1, 100, 200, 1);
         assert_eq!(WireOrder::from_sol(&x).to_sol().unwrap(), x);
         let mut w = WireOrder::from_sol(&x);
-        w.sell_amount = "01".into();
+        w.amount = "01".into();
         assert!(w.to_sol().is_err());
+        let mut v = serde_json::to_value(WireOrder::from_sol(&x)).unwrap();
+        v["maker"] = serde_json::json!("0x00");
+        assert!(serde_json::from_value::<WireOrder>(v).is_err(), "the built DEX's fields are refused");
     }
 
     #[test]
@@ -843,34 +856,69 @@ mod tests {
         put(&mut b, ask(2, 10, 20, 1)); // 2.0 best
         put(&mut b, ask(3, 10, 20, 2)); // 2.0, later
         let p = put(&mut b, bid(9, 60, 30, 1)); // buys up to 30 base at <= 2.0 → fills 2 and 3 only
-        let makers: Vec<Address> = p.fills.iter().map(|f| f.maker.order.maker).collect();
-        assert_eq!(makers, vec![Address::repeat_byte(2), Address::repeat_byte(3)]);
-        let rest = p.rested.expect("bid remainder rests");
-        assert_eq!(rest.remaining, U256::from(20)); // 60 - 40 quote left
-        assert_eq!(b.len(), 2); // ask@3.0 and the bid remainder
+        let who: Vec<Address> = makers(&p).iter().map(|m| m.0).collect();
+        assert_eq!(who, vec![Address::repeat_byte(2), Address::repeat_byte(3)], "one settlement, two makers");
+        assert!(settlement_ok(p.settlement.as_ref().unwrap()));
+        assert_eq!(p.settlement.as_ref().unwrap().taker_fill, U256::from(40));
+        // 20 quote left, still crossing nothing at <= 2.0: rests
+        assert_eq!(p.rested.expect("bid remainder rests").remaining, U256::from(20));
+        assert_eq!(b.len(), 2);
     }
 
     #[test]
-    fn partial_fill_executes_at_the_makers_price_and_keeps_the_maker_resting() {
+    fn a_partial_fill_runs_at_the_makers_price_and_keeps_the_maker_resting() {
         let mut b = Book::new(vec![market()]);
         put(&mut b, ask(1, 100, 200, 1));
-        let p = put(&mut b, bid(2, 100, 40, 1)); // willing to pay 2.5
-        assert_eq!(p.fills.len(), 1);
-        let f = &p.fills[0];
-        // 100 quote at maker price 2.0 buys 50 base; the maker has 100 → x = 50, y = 100
-        assert_eq!((f.maker_fill, f.taker_fill), (U256::from(50), U256::from(100)));
-        assert!(limits_ok(&f.maker, &f.taker, f.maker_fill, f.taker_fill));
-        let left = b.open_of(Address::repeat_byte(1));
-        assert_eq!(left[0].remaining, U256::from(50));
+        let p = put(&mut b, bid(2, 120, 48, 1)); // pays up to 2.5; 120 quote buys 60 base at 2.0
+        assert_eq!(makers(&p), vec![(Address::repeat_byte(1), U256::from(60), U256::from(120))]);
+        assert!(settlement_ok(p.settlement.as_ref().unwrap()));
+        assert_eq!(b.open_of(Address::repeat_byte(1))[0].remaining, U256::from(40));
         assert!(p.rested.is_none());
     }
 
+    /// NODE-DEX-15: every order fills at least `max(minFill, ceil(amount / 2))` per settlement unless it closes.
+    #[test]
+    fn the_minimum_fill_binds_makers_and_takers() {
+        let mut b = Book::new(vec![market()]);
+        put(&mut b, ask(1, 100, 200, 1)); // min 50 base
+        // a bid that can take only 20 base cannot partially fill a 100 ask: no settlement, and its remainder would
+        // rest crossed, so it is cancelled
+        let p = put(&mut b, bid(2, 40, 20, 1));
+        assert!(p.settlement.is_none());
+        assert_eq!((p.dropped, p.rested.is_none()), (U256::from(40), true));
+        assert_eq!(b.open_of(Address::repeat_byte(1))[0].remaining, U256::from(100));
+        // a taker whose crossing makers give less than its own minimum: nothing settles, it rests (GTC)
+        let mut b = Book::new(vec![market()]);
+        put(&mut b, ask(1, 10, 20, 1));
+        let p = put(&mut b, bid(3, 200, 100, 1)); // min 100 quote; the ask fills only 20 quote
+        assert!(p.settlement.is_none());
+        assert!(p.dropped == U256::from(200), "crossing remainder never rests");
+        // the same taker with a deeper maker: one settlement of two makers reaches its minimum
+        let mut b = Book::new(vec![market()]);
+        put(&mut b, ask(1, 10, 20, 1));
+        put(&mut b, ask(4, 50, 100, 1));
+        let p = put(&mut b, bid(3, 200, 100, 1));
+        assert_eq!(makers(&p).len(), 2);
+        assert_eq!(p.settlement.as_ref().unwrap().taker_fill, U256::from(120));
+        assert!(settlement_ok(p.settlement.as_ref().unwrap()));
+    }
+
+    #[test]
+    fn a_maker_too_large_for_the_taker_is_skipped_for_a_deeper_one() {
+        let mut b = Book::new(vec![market()]);
+        put(&mut b, ask(1, 100, 200, 1)); // best price, min 50
+        put(&mut b, ask(2, 10, 21, 1));   // worse price, closes whole
+        let p = put(&mut b, bid(3, 25, 10, 1)); // pays up to 2.5, buys ~10 base
+        assert_eq!(makers(&p), vec![(Address::repeat_byte(2), U256::from(10), U256::from(21))]);
+        assert!(settlement_ok(p.settlement.as_ref().unwrap()));
+    }
+
     #[test]
     fn non_crossing_orders_rest_on_both_sides() {
         let mut b = Book::new(vec![market()]);
         put(&mut b, ask(1, 10, 30, 1));
         let p = put(&mut b, bid(2, 20, 10, 1));
-        assert!(p.fills.is_empty());
+        assert!(p.settlement.is_none());
         let (bids, asks) = b.depth(1, 10).unwrap();
         assert_eq!((bids.len(), asks.len()), (1, 1));
     }
@@ -878,53 +926,92 @@ mod tests {
     #[test]
     fn ioc_remainder_is_dropped_not_rested() {
         let mut b = Book::new(vec![market()]);
-        put(&mut b, ask(1, 10, 20, 1));
+        put(&mut b, ask(1, 30, 60, 1));
         let mut x = bid(2, 100, 50, 1);
         x.flags = FLAG_IOC;
         let p = put(&mut b, x);
-        assert_eq!(p.fills.len(), 1);
-        assert_eq!(p.dropped, U256::from(80));
+        assert_eq!(makers(&p).len(), 1);
+        assert_eq!(p.dropped, U256::from(40));
         assert!(p.rested.is_none());
         assert!(b.is_empty());
     }
 
     #[test]
-    fn fok_fills_whole_against_one_maker_or_nothing() {
+    fn fill_or_kill_aggregates_makers_or_settles_nothing() {
         let mut b = Book::new(vec![market()]);
-        put(&mut b, ask(1, 10, 20, 1)); // too small for the FOK
-        put(&mut b, ask(3, 100, 200, 1));
+        put(&mut b, ask(1, 10, 20, 1));
+        put(&mut b, ask(3, 20, 40, 1));
         let mut x = bid(2, 60, 30, 1);
-        x.flags = FLAG_FOK;
-        let p = put(&mut b, x.clone());
-        assert_eq!(p.fills.len(), 1, "skips the small maker, fills whole against one");
-        assert_eq!(p.fills[0].maker.order.maker, Address::repeat_byte(3));
-        assert_eq!(p.fills[0].taker_fill, U256::from(60));
+        x.minFill = x.amount; // FOK
+        let p = put(&mut b, x);
+        assert_eq!(makers(&p).len(), 2, "one atomic settlement may aggregate makers");
+        assert_eq!(p.settlement.as_ref().unwrap().taker_fill, U256::from(60));
         let mut y = bid(4, 1_000, 500, 1);
-        y.flags = FLAG_FOK;
+        y.minFill = y.amount;
+        let mut b = Book::new(vec![market()]);
+        put(&mut b, ask(1, 10, 20, 1));
         let p = put(&mut b, y);
-        assert!(p.fills.is_empty());
-        assert_eq!(p.dropped, U256::from(1_000));
+        assert!(p.settlement.is_none());
+        assert_eq!(p.dropped, U256::from(1_000), "a FOK remainder that crosses never rests");
     }
 
     #[test]
-    fn self_trade_is_skipped() {
+    fn self_trade_and_cheap_makers_are_skipped() {
+        let mut m = market();
+        m.maker_fee_ppm = 1_000;
+        let mut b = Book::new(vec![m]);
+        let mut cheap = ask(5, 10, 20, 1);
+        cheap.fee = U256::from(999);
+        let mut own = ask(1, 10, 20, 1);
+        own.fee = U256::from(1_000);
+        let mut fair = ask(2, 10, 20, 1);
+        fair.fee = U256::from(1_000);
+        b.insert(Resting { hash: hash_of(&cheap), sell: BASE, order: cheap, sig: Bytes::new(), remaining: U256::from(10), seq: 1 });
+        put(&mut b, own);
+        put(&mut b, fair);
+        let p = put(&mut b, bid(1, 20, 10, 2));
+        assert_eq!(makers(&p), vec![(Address::repeat_byte(2), U256::from(10), U256::from(20))]);
+    }
+
+    #[test]
+    fn dust_makers_leave_the_book() {
         let mut b = Book::new(vec![market()]);
-        put(&mut b, ask(1, 10, 20, 1));
+        // 1 base left of an order pricing 1 base at 1/3 quote: it can never receive one unit
+        let dust = ask(1, 3, 1, 1);
+        b.insert(Resting { hash: hash_of(&dust), sell: BASE, order: dust, sig: Bytes::new(), remaining: U256::from(1), seq: 1 });
         put(&mut b, ask(2, 10, 20, 1));
-        let p = put(&mut b, bid(1, 20, 10, 2));
-        assert_eq!(p.fills.len(), 1);
-        assert_eq!(p.fills[0].maker.order.maker, Address::repeat_byte(2));
+        let p = put(&mut b, bid(3, 20, 10, 1));
+        assert_eq!(p.dust.len(), 1);
+        assert_eq!(makers(&p), vec![(Address::repeat_byte(2), U256::from(10), U256::from(20))]);
+        assert!(b.is_empty());
     }
 
     #[test]
-    fn limits_mirror_the_contract_including_rounding() {
-        // maker 3 base for 10 quote (3.33); taker sells 10 quote for 3 base (same price)
-        let m = Resting { hash: B256::ZERO, order: ask(1, 3, 10, 1), sig: Bytes::new(), remaining: U256::from(3), seq: 1 };
-        let t = Resting { hash: B256::ZERO, order: bid(2, 10, 3, 1), sig: Bytes::new(), remaining: U256::from(10), seq: 2 };
+    fn limits_and_the_settlement_mirror_the_contract_including_rounding() {
+        // maker 3 base for 10 quote (3.33); the taker sells 10 quote for 3 base (same price)
+        let m = Resting { hash: B256::ZERO, sell: BASE, order: ask(1, 3, 10, 1), sig: Bytes::new(), remaining: U256::from(3), seq: 1 };
+        let t = Resting { hash: B256::repeat_byte(1), sell: QUOTE, order: bid(2, 10, 3, 1), sig: Bytes::new(), remaining: U256::from(10), seq: 2 };
         assert!(limits_ok(&m, &t, U256::from(3), U256::from(10)));
-        // 1 base would cost ceil(10/3) = 4 quote: 4/1 > 10/3 breaks the taker's limit
+        // 1 base costs ceil(10/3) = 4 quote: 4/1 > 10/3 breaks the taker's limit
         assert!(!limits_ok(&m, &t, U256::from(1), U256::from(4)));
         assert!(!limits_ok(&m, &t, U256::from(4), U256::from(14)), "overfill");
+        assert!(!limits_ok(&m, &t, U256::from(3), U256::from(9)), "y is the maker's ceiling receive, not less");
+        let s = |makers: Vec<(Resting, U256, U256)>, fill: u64| PlannedSettlement {
+            tag: B256::ZERO, market_id: 1, taker: t.clone(), taker_fill: U256::from(fill), makers };
+        assert!(settlement_ok(&s(vec![(m.clone(), U256::from(3), U256::from(10))], 10)));
+        assert!(!settlement_ok(&s(vec![(m.clone(), U256::from(3), U256::from(10))], 9)), "FillMismatch");
+        assert!(!settlement_ok(&s(vec![], 0)), "NoMakers");
+        let mut twice = m.clone();
+        twice.remaining = U256::from(6);
+        assert!(!settlement_ok(&s(vec![(twice.clone(), U256::from(1), U256::from(4)), (twice, U256::from(1), U256::from(4))], 8)),
+            "DuplicateOrder");
+        let mut me = m.clone();
+        me.order.from = t.order.from;
+        assert!(!settlement_ok(&s(vec![(me, U256::from(3), U256::from(10))], 10)), "SelfTrade");
+        let mut big = m.clone();
+        big.order = ask(1, 30, 100, 1);
+        big.remaining = U256::from(30);
+        assert!(!settlement_ok(&s(vec![(big, U256::from(3), U256::from(10))], 10)), "maker below its minimum");
     }
 
     #[test]
@@ -934,15 +1021,14 @@ mod tests {
         put(&mut b, ask(2, 10, 20, 1));
         put(&mut b, ask(3, 10, 20, 2));
         put(&mut b, bid(4, 10, 10, 1));
-        put(&mut b, bid(5, 100, 40, 1)); // partially fills ask 2 & 3
+        put(&mut b, bid(5, 40, 20, 1)); // fills asks 2 and 3
         let rows = b.rows();
         let json = serde_json::to_string(&rows).unwrap();
         let back: Vec<Row> = serde_json::from_str(&json).unwrap();
         let mut c = Book::load(vec![market()], &back).unwrap();
         assert_eq!(c.rows(), rows);
         assert_eq!(c.depth(1, 10), b.depth(1, 10));
-        // the restarted book matches exactly like the original
-        let strip = |p: Placement| p.fills.into_iter().map(|f| (f.maker, f.taker, f.maker_fill, f.taker_fill)).collect::<Vec<_>>();
+        let strip = |p: Placement| makers(&p);
         let pb = put(&mut b, bid(6, 30, 10, 1));
         let pc = put(&mut c, bid(6, 30, 10, 1));
         assert_eq!(strip(pb), strip(pc));
@@ -954,13 +1040,14 @@ mod tests {
         put(&mut b, ask(1, 10, 20, 1));
         let p = put(&mut b, bid(2, 20, 10, 1));
         assert!(b.is_empty());
-        let f = &p.fills[0];
-        assert!(b.restore(f.maker.clone(), f.maker_fill).fills.is_empty());
+        let s = p.settlement.unwrap();
+        let (m, x, _) = s.makers[0].clone();
+        assert!(b.restore(m.clone(), x).settlement.is_none());
         assert_eq!(b.open_of(Address::repeat_byte(1))[0].remaining, U256::from(10));
-        assert_eq!(b.open_of(Address::repeat_byte(1))[0].seq, f.maker.seq, "time priority kept");
-        let mut ioc = f.taker.clone();
+        assert_eq!(b.open_of(Address::repeat_byte(1))[0].seq, m.seq, "time priority kept");
+        let mut ioc = s.taker.clone();
         ioc.order.flags = FLAG_IOC;
-        b.restore(ioc, f.taker_fill);
+        b.restore(ioc, s.taker_fill);
         assert!(b.open_of(Address::repeat_byte(2)).is_empty());
     }
 
@@ -968,115 +1055,117 @@ mod tests {
     fn restoring_both_sides_rematches_instead_of_leaving_a_crossed_book() {
         let mut b = Book::new(vec![market()]);
         put(&mut b, ask(1, 10, 20, 1));
-        let p = put(&mut b, bid(2, 20, 10, 1));
-        let f = p.fills[0].clone();
-        assert!(b.restore(f.maker.clone(), f.maker_fill).fills.is_empty());
-        let again = b.restore(f.taker.clone(), f.taker_fill);
-        assert_eq!(again.fills.len(), 1, "the two healthy sides trade again");
-        assert_eq!((again.fills[0].maker_fill, again.fills[0].taker_fill), (f.maker_fill, f.taker_fill));
-        assert_ne!(again.fills[0].tag, f.tag, "a re-match is a new trade, not a replay");
+        let s = put(&mut b, bid(2, 20, 10, 1)).settlement.unwrap();
+        let (m, x, _) = s.makers[0].clone();
+        assert!(b.restore(m, x).settlement.is_none());
+        let again = b.restore(s.taker.clone(), s.taker_fill).settlement.expect("the two healthy sides trade again");
+        assert_eq!((again.taker_fill, again.makers[0].1), (s.taker_fill, s.makers[0].1));
+        assert_ne!(again.tag, s.tag, "a re-match is a new trade, not a replay");
         assert!(b.is_empty());
     }
 
     #[test]
-    fn admit_enforces_spam_caps() {
+    fn admit_enforces_the_intake_rules() {
         let mut b = Book::new(vec![market()]);
         let good = ask(1, 100, 200, 1);
-        let ok = |b: &Book, x: &Order, fundable: u64| {
-            b.admit(hash_of(x), x, x.sellAmount, U256::from(fundable), U256::ZERO, RELAYER, NOW)
+        let ok = |b: &Book, x: &TradeOrder, fundable: u64| {
+            b.admit(hash_of(x), sell_of(x), x, x.amount, U256::from(fundable), RELAYER, DEX, NOW)
         };
         ok(&b, &good, 100).unwrap();
         // committed balance: the same 100 cannot back two orders (review D6)
         put(&mut b, good.clone());
         assert!(ok(&b, &ask(1, 100, 200, 2), 150).is_err());
         ok(&b, &ask(1, 50, 100, 2), 150).unwrap();
-        let mut x = ask(1, 1, 2, 3);
-        x.relayer = Address::ZERO;
-        assert!(ok(&b, &x, 1_000).is_err(), "RS5-9");
-        let mut x = ask(1, 1, 2, 3);
-        x.expiry = U256::from(NOW + 2);
-        assert!(ok(&b, &x, 1_000).is_err(), "expiry too short");
-        x.expiry = U256::from(NOW + MAX_TTL_SECS + 1);
-        assert!(ok(&b, &x, 1_000).is_err(), "expiry too long");
-        let mut x = ask(1, 1, 2, 3);
-        x.sellAmount = U256::from(1u8) << 128;
-        assert!(ok(&b, &x, 1_000).is_err(), "2^128");
-        let mut x = ask(1, 1, 2, 3);
-        x.flags = FLAG_FOK | FLAG_IOC;
-        assert!(ok(&b, &x, 1_000).is_err());
-        assert!(ok(&b, &o(1, BASE, 1, Address::repeat_byte(0xcc), 1, 9), 1_000).is_err(), "no market");
+        let bad = |f: &dyn Fn(&mut TradeOrder)| {
+            let mut x = ask(1, 1, 2, 3);
+            f(&mut x);
+            ok(&b, &x, 1_000).is_err()
+        };
+        assert!(bad(&|x| x.relayer = Address::ZERO), "RS5-9: home-bound");
+        assert!(bad(&|x| x.dex = Address::repeat_byte(0xd1)), "NODE-DEX-16");
+        assert!(bad(&|x| x.validUntil = U256::from(NOW + 2)), "too short");
+        assert!(bad(&|x| x.validUntil = U256::from(NOW + MAX_TTL_SECS + 1)), "too long");
+        assert!(bad(&|x| x.amount = U256::from(1u8) << 128), "2^128");
+        assert!(bad(&|x| x.flags = FLAG_ESCROW | FLAG_IOC), "Path B not served");
+        assert!(bad(&|x| x.flags = 8), "unknown flag");
+        assert!(bad(&|x| x.minFill = U256::from(2)), "minFill above amount");
+        assert!(bad(&|x| x.fee = U256::from(10_001)), "fee above 1 %");
+        assert!(bad(&|x| x.receiveToken = Address::repeat_byte(0xcc)), "no market");
+        assert!(!bad(&|x| x.flags = FLAG_LISTED_POOLS), "LISTED_POOLS is fine on the book");
         assert!(ok(&b, &good, 1_000).is_err(), "duplicate");
         for n in 10..(10 + MAX_OPEN_PER_MAKER as u64) {
             put(&mut b, ask(7, 1, 2, n));
         }
-        assert!(ok(&b, &ask(7, 1, 2, 999), 1_000).is_err(), "per-maker cap");
+        assert!(ok(&b, &ask(7, 1, 2, 999), 1_000).is_err(), "per-signer cap");
         // minimum size on the base side, both directions (review D22)
         let mut m = market();
         m.min_base_amount = "10".into();
         let b2 = Book::new(vec![m]);
-        assert!(b2.admit(B256::ZERO, &ask(1, 5, 10, 1), U256::from(5), U256::from(99), U256::ZERO, RELAYER, NOW).is_err());
-        assert!(b2.admit(B256::ZERO, &bid(1, 50, 5, 1), U256::from(50), U256::from(99), U256::ZERO, RELAYER, NOW).is_err());
-        b2.admit(B256::ZERO, &bid(1, 50, 10, 1), U256::from(50), U256::from(99), U256::ZERO, RELAYER, NOW).unwrap();
+        assert!(b2.admit(B256::ZERO, BASE, &ask(1, 5, 10, 1), U256::from(5), U256::from(99), RELAYER, DEX, NOW).is_err());
+        assert!(b2.admit(B256::ZERO, QUOTE, &bid(1, 50, 5, 1), U256::from(50), U256::from(99), RELAYER, DEX, NOW).is_err());
+        b2.admit(B256::ZERO, QUOTE, &bid(1, 50, 10, 1), U256::from(50), U256::from(99), RELAYER, DEX, NOW).unwrap();
+        assert!(b2.admit(B256::ZERO, QUOTE, &bid(1, 50, 10, 1), U256::ZERO, U256::from(99), RELAYER, DEX, NOW).is_err(), "closed");
     }
 
     #[test]
-    fn poison_orders_never_block_the_book() {
-        // review I2: a private order or a fee cap below the market fee would fail every pair it joins
+    fn fee_rates_by_role_at_intake() {
         let mut m = market();
-        (m.fee_on, m.maker_fee_ppm, m.taker_fee_ppm) = (true, 1_000, 2_000);
+        (m.maker_fee_ppm, m.taker_fee_ppm) = (1_000, 2_000);
         let mut b = Book::new(vec![m]);
-        let ok = |b: &Book, x: &Order| b.admit(hash_of(x), x, x.sellAmount, U256::from(1_000), U256::ZERO, RELAYER, NOW);
-        let mut x = ask(1, 100, 200, 1);
-        x.maxFeePpm = 1_999;
-        assert!(ok(&b, &x).is_err(), "cap below the taker fee");
-        x.maxFeePpm = 2_000;
-        ok(&b, &x).unwrap();
-        x.taker = Address::repeat_byte(9);
-        assert!(ok(&b, &x).is_err(), "private order");
-        // a resting order whose cap fell under a raised fee is skipped, the next one trades
-        let mut cheap = ask(1, 100, 100, 2);
-        cheap.maxFeePpm = 500;
-        put(&mut b, cheap);
-        let mut fair = ask(2, 100, 200, 3);
-        fair.maxFeePpm = 2_000;
-        put(&mut b, fair.clone());
-        let mut t = bid(3, 200, 100, 4);
-        t.maxFeePpm = 2_000;
-        let p = put(&mut b, t.clone());
-        assert_eq!(p.fills.len(), 1);
-        assert_eq!(p.fills[0].maker.hash, hash_of(&fair));
-        // a taker whose cap is under the taker fee never matches
-        let mut low = bid(4, 200, 100, 5);
-        low.maxFeePpm = 1_000;
-        assert!(put(&mut b, low).fills.is_empty());
+        let ok = |b: &Book, x: &TradeOrder| b.admit(hash_of(x), sell_of(x), x, x.amount, U256::from(1_000), RELAYER, DEX, NOW);
+        let with = |fee: u64, flags: u8| {
+            let mut x = ask(1, 100, 200, 1);
+            (x.fee, x.flags) = (U256::from(fee), flags);
+            x
+        };
+        assert!(ok(&b, &with(999, 0)).is_err(), "a GTC order below the maker rate never fills");
+        ok(&b, &with(1_000, 0)).unwrap();
+        assert!(ok(&b, &with(1_999, FLAG_IOC)).is_err(), "IOC only takes");
+        ok(&b, &with(2_000, FLAG_IOC)).unwrap();
+        let mut cross = bid(9, 200, 100, 1);
+        cross.fee = U256::from(2_000);
+        put(&mut b, cross);
+        assert!(ok(&b, &with(1_000, 0)).is_err(), "a GTC order that takes on arrival pays the taker rate");
+        ok(&b, &with(2_000, 0)).unwrap();
     }
 
+    /// A handed-back order that may not take (fee under the taker rate) rests even when crossing; makers first
+    /// restores the original roles (the venue's sync order).
     #[test]
-    fn admit_counts_the_relayer_fee_on_top() {
-        let b = Book::new(vec![market()]);
-        let mut x = ask(1, 100, 200, 1);
-        x.feeMode = 1;
-        x.fee = U256::from(10_000); // 1 %
-        assert!(b.admit(B256::ZERO, &x, x.sellAmount, U256::from(100), U256::ZERO, RELAYER, NOW).is_err());
-        b.admit(B256::ZERO, &x, x.sellAmount, U256::from(101), U256::ZERO, RELAYER, NOW).unwrap();
-        assert_eq!(relayer_fee(&x, U256::from(40)), (BASE, U256::ZERO)); // 40 * 1% floors to 0
-        x.feeMode = 2;
-        x.fee = U256::from(3);
-        x.feeToken = Address::repeat_byte(0xf0);
-        assert_eq!(relayer_fee(&x, U256::from(40)).1, U256::from(1)); // 3*40/100 floors
+    fn a_hand_back_below_the_taker_rate_rests() {
+        let mut m = market();
+        (m.maker_fee_ppm, m.taker_fee_ppm) = (1_000, 2_000);
+        let mut b = Book::new(vec![m]);
+        let mut x = ask(1, 10, 20, 1);
+        x.fee = U256::from(1_000);
+        let mut y = bid(2, 20, 10, 1);
+        y.fee = U256::from(2_000);
+        let mk = |o: &TradeOrder| Resting { hash: hash_of(o), sell: sell_of(o), order: o.clone(), sig: Bytes::new(), remaining: o.amount, seq: 1 };
+        assert!(b.restore(mk(&y), y.amount).rested.is_some());
+        let p = b.restore(mk(&x), x.amount);
+        assert!(p.settlement.is_none() && p.rested.is_some(), "the cheap ask may not take: it rests crossed");
+        let mut c = Book::new(vec![b.markets().next().unwrap().clone()]);
+        assert!(c.restore(mk(&x), x.amount).rested.is_some());
+        assert!(c.restore(mk(&y), y.amount).settlement.is_some(), "makers first: the bid takes again");
     }
 
     #[test]
     fn purge_and_drop_below() {
         let mut b = Book::new(vec![market()]);
         let mut x = ask(1, 10, 20, 1);
-        x.expiry = U256::from(NOW + 10);
+        x.validUntil = U256::from(NOW + 10);
         put(&mut b, x);
         put(&mut b, ask(2, 10, 20, 5));
         put(&mut b, ask(2, 10, 20, 9));
+        let mut other_lane = ask(2, 10, 20, 2);
+        other_lane.batch = U256::from(2);
+        put(&mut b, other_lane);
         assert_eq!(b.purge(NOW + 11).len(), 1);
-        assert_eq!(b.drop_below(Address::repeat_byte(2), U256::from(6)).len(), 1);
-        assert_eq!(b.len(), 1);
+        let all = |_: Address| true;
+        assert_eq!(b.drop_below(Address::repeat_byte(2), U256::from(1), U256::from(6), &all).len(), 1, "lane 1 only");
+        assert_eq!(b.drop_below(Address::repeat_byte(2), U256::from(1), U256::from(99), &|s| s == QUOTE).len(), 0,
+            "another sell token's lane");
+        assert_eq!(b.len(), 2);
     }
 
     #[test]
@@ -1085,4 +1174,15 @@ mod tests {
         assert_eq!(price_str(U256::from(2_000_000_000u64), U256::from(10u64).pow(U256::from(18)), 18, 6), "2000");
         assert_eq!(price_str(U256::from(1u8), U256::from(3u8), 0, 0), "0.333333333333333333");
     }
+
+    #[test]
+    fn a_planned_settlement_encodes_as_the_dex_reads_it() {
+        let mut b = Book::new(vec![market()]);
+        put(&mut b, ask(1, 10, 20, 1));
+        let s = put(&mut b, bid(2, 20, 10, 1)).settlement.unwrap();
+        let st = s.to_settlement();
+        assert_eq!((st.r#ref, st.taker.sellToken, st.taker.fill), (s.tag, QUOTE, U256::from(20)));
+        assert_eq!((st.makers[0].sellToken, st.makers[0].fill), (BASE, U256::from(10)));
+        assert_eq!(&ISCaaSDex::mtxSettleCall { s: vec![st] }.abi_encode()[..4], &[0xb0, 0x95, 0x5d, 0xd6]);
+    }
 }
diff --git a/scaas-node/src/dex/venue.rs b/scaas-node/src/dex/venue.rs
index cdb2c61..6b5e8a0 100644
--- a/scaas-node/src/dex/venue.rs
+++ b/scaas-node/src/dex/venue.rs
@@ -1,9 +1,13 @@
-//! DEX venue: phần I/O quanh `Book` (design §2–§3). Một venue mỗi chain, người ghi DUY NHẤT của sổ.
+//! DEX venue: the I/O around `Book` (NODE-DEX-01, -15, -16). One venue per chain and DEX, the book's ONLY writer.
 //!
-//! - Lưu bền ở Odoo qua `/json/2` (RS5-2): mỗi thay đổi sổ là MỘT `dex_book_commit` (lệnh + trade +
-//!   relay job `call`), thành công mới thay sổ trong bộ nhớ; lỗi ⇒ nạp lại sổ từ Odoo (review D20).
-//! - Settle đi qua outbox Odoo như mọi job khác: `submit` claim, journal `signed`, thay thế, lấp nonce.
-//! - Watcher event final có cursor riêng (RS5-8): DEX lỗi không chặn chốt thanh toán.
+//! - Persisted in the client over `/json/2` (RS5-2): every book change is ONE `dex_book_commit` (orders + trades +
+//!   jobs); only success replaces the book in memory; a failure reloads the book from the client (review D20).
+//! - Settlements go through the client outbox like every job: `mtxSettle` and the DEX-side cancels as `call` jobs to
+//!   the DEX, the token-side cancels as `metatx` jobs naming their `entry` (job-api.md, order and wrap entries).
+//! - Intake reads the order's state where it lives (NODE-DEX-15, dex.md §10): a SCaaS sell token keeps a
+//!   `TradeOrder`'s fill state and cancels (`tradeOrderDigest`, `pulled`, `minNonce`, `balanceOf`), the DEX keeps an
+//!   outside token's `DexOrder` (`dexOrderDigest`, `pulled`, `minNonce`, and `allowance(from, puller)`).
+//! - The final-event watcher has its own cursor (RS5-8): a DEX failure never blocks payment finality.
 use std::collections::{HashMap, VecDeque};
 use std::sync::Arc;
 use std::time::Duration;
@@ -12,7 +16,7 @@ use alloy::primitives::{Address, Bytes, B256, U256};
 use alloy::providers::Provider;
 use alloy::rpc::types::{Filter, Log, TransactionRequest};
 use alloy::signers::Signature;
-use alloy::sol_types::{Eip712Domain, SolCall, SolError, SolEvent, SolInterface};
+use alloy::sol_types::{SolCall, SolEvent};
 use anyhow::{anyhow, bail, Context, Result};
 use serde::{Deserialize, Serialize};
 use serde_json::{json, Value};
@@ -20,23 +24,26 @@ use tokio::sync::Mutex;
 use tracing::{info, warn};
 
 use super::{
-    cancel_digest, domain, hex_bytes, hex_of, invalidate_digest, order_hash, pair, Book, CancelReq, ISCaaSDex,
-    MarketCfg, Order, PlannedFill, Resting, Row, WireOrder, FLAG_FOK, FLAG_IOC, ST_OK, relayer_fee,
+    hex_bytes, hex_of, pair, Book, DexOrder, ISCaaSDex, MarketCfg, PlannedSettlement, Resting, Row,
+    TradeOrder, WireOrder, FLAG_IOC, KIND_OUTSIDE, KIND_SCAAS,
 };
+use crate::abi::IToken;
 use crate::chain::{classify, Chain, SimError};
 use crate::finality::{next_range, quorum_ok, safe_head, Mode};
 use crate::odoo::Odoo;
 use crate::submit::now;
 
-/// Lần thử lại khi simulate loại lệnh nghỉ hỏng (design §2 bước 2).
+/// Rounds of "drop the maker at fault and match again" before giving up (NODE-DEX-02).
 const MAX_ROUNDS: usize = 3;
 const RECENT_TRADES: usize = 200;
-/// Huỷ on-chain tốn gas relayer: mỗi maker tối đa chừng này mỗi giờ (review D14).
+/// On-chain cancels cost relayer gas: at most this many per signer per hour (review D14).
 const ONCHAIN_CANCELS_PER_HOUR: usize = 20;
 const CANCEL_BATCH: usize = 50;
 const MAX_LOG_SPAN: u64 = 1000;
+/// Cancels and invalidations never expire on chain; the job carrying one is given a day.
+const CANCEL_JOB_SECS: u64 = 86_400;
 
-/// Lỗi trả cho client: `Bad` = 400 (lỗi của lệnh), `Unavailable` = 503 (RPC/Odoo).
+/// Error for the client: `Bad` = 400 (the order's fault), `Unavailable` = 503 (RPC or client store).
 #[derive(Debug)]
 pub enum VenueError {
     Bad(String),
@@ -88,14 +95,19 @@ struct LoadReply {
     rows: Vec<Row>,
 }
 
+/// One leg of a failed trade; `row` None = the order is closed in the client (cancelled/expired/invalid): never
+/// handed back (review I3).
+#[derive(Debug, Deserialize)]
+struct FailedLeg {
+    row: Option<Row>,
+    fill: String,
+}
+
 #[derive(Debug, Deserialize)]
 struct FailedTrade {
     tag: String,
-    /// None: lệnh đã đóng ở Odoo (huỷ/hết hạn/invalid) — không bao giờ trả về sổ (review I3).
-    maker: Option<Row>,
-    taker: Option<Row>,
-    maker_fill: String,
-    taker_fill: String,
+    taker: FailedLeg,
+    makers: Vec<FailedLeg>,
 }
 
 #[derive(Debug, Deserialize)]
@@ -108,7 +120,7 @@ struct CursorReply {
     indexed_block: u64,
 }
 
-/// Một thay đổi sổ, ghi vào Odoo trong MỘT transaction (`dex_book_commit`).
+/// One book change, written to the client in ONE transaction (`dex_book_commit`).
 #[derive(Debug, Default, Serialize)]
 pub struct Commit {
     pub orders: Vec<Value>,
@@ -125,7 +137,7 @@ impl Commit {
     fn order(&mut self, market_id: i64, r: &Resting, state: &str) {
         let row = Row::of(r);
         self.orders.push(json!({
-            "market_id": market_id, "order_hash": row.order_hash, "order": row.order,
+            "market_id": market_id, "order_hash": row.order_hash, "sell_token": row.sell_token, "order": row.order,
             "signature": row.signature, "remaining": row.remaining, "seq": row.seq, "state": state,
         }));
     }
@@ -134,37 +146,29 @@ impl Commit {
 fn state_of(r: &Resting) -> &'static str {
     if r.remaining.is_zero() {
         "filled"
-    } else if r.remaining < r.order.sellAmount {
+    } else if r.remaining < r.order.amount {
         "partial"
     } else {
         "open"
     }
 }
 
-pub struct Venue {
-    pub chain: Arc<Chain>,
-    relay: Odoo,
-    indexer: Option<Odoo>,
-    pub dex: Address,
-    domain: Eip712Domain,
-    book: Mutex<Book>,
-    trades: std::sync::Mutex<VecDeque<TradeView>>,
-    cancels: std::sync::Mutex<CancelQueue>,
-}
+/// An on-chain cancel waiting for the next sync: `(market, sell token, its kind, order, CancelOrder signature)`.
+type PendingCancel = (i64, Address, u8, TradeOrder, Bytes);
 
 #[derive(Default)]
 struct CancelQueue {
-    // ponytail: hàng đợi trong bộ nhớ — node chết trước khi flush thì lệnh đã gỡ khỏi sổ (và Odoo ghi
-    // `cancelled`) nhưng chưa đóng on-chain; vì RS5-9 chỉ relayer này settle được nó nên an toàn.
-    // Muốn bền: lưu chữ ký huỷ vào `blockchain.dex.order` và flush từ Odoo.
-    pending: Vec<(i64, CancelReq)>,
+    // ponytail: in memory — a node that dies before the flush has the order out of the book (the client records
+    // `cancelled`) but not closed on chain; with RS5-9 only this relayer can settle it, so it is safe. Durable: keep
+    // the cancel signature on the client's order row and flush from there.
+    pending: Vec<PendingCancel>,
     recent: HashMap<Address, Vec<u64>>,
 }
 
 impl CancelQueue {
-    /// Có được huỷ on-chain lần nữa trong giờ này không (và ghi nhận nếu có).
-    fn allow(&mut self, maker: Address, at: u64) -> bool {
-        let v = self.recent.entry(maker).or_default();
+    /// May `from` cancel on chain once more this hour (and record it if so).
+    fn allow(&mut self, from: Address, at: u64) -> bool {
+        let v = self.recent.entry(from).or_default();
         v.retain(|t| at < t + 3600);
         if v.len() >= ONCHAIN_CANCELS_PER_HOUR {
             return false;
@@ -174,8 +178,27 @@ impl CancelQueue {
     }
 }
 
+/// An order's state on chain: what is left to fill and what the signer can still deliver.
+struct OnChain {
+    remaining: U256,
+    fundable: U256,
+}
+
+pub struct Venue {
+    pub chain: Arc<Chain>,
+    relay: Odoo,
+    indexer: Option<Odoo>,
+    pub dex: Address,
+    puller: Address,
+    /// `tokenKind` per token, from the DEX's listing (never from the order or the client).
+    kinds: HashMap<Address, u8>,
+    book: Mutex<Book>,
+    trades: std::sync::Mutex<VecDeque<TradeView>>,
+    cancels: std::sync::Mutex<CancelQueue>,
+}
+
 impl Venue {
-    /// Nạp thị trường + sổ từ Odoo, đối chiếu thị trường với chain (design §3.1).
+    /// Load the markets and the book from the client; serve only markets the DEX lists with both tokens classified.
     pub async fn start(chain: Arc<Chain>, relay: Odoo, indexer: Option<Odoo>, dex: Address) -> Result<Arc<Self>> {
         let n = chain.number;
         let mr: MarketsReply = relay
@@ -183,13 +206,19 @@ impl Venue {
             .await
             .context("dex_markets")?;
         if mr.dex != dex {
-            bail!("chain {n}: Odoo DEX {:#x} != node config {dex:#x}", mr.dex);
+            bail!("chain {n}: client DEX {:#x} != node config {dex:#x}", mr.dex);
         }
+        let puller = view(&chain, dex, ISCaaSDex::pullerCall {}).await.context("puller()")?;
         let mut markets = vec![];
+        let mut kinds = HashMap::new();
         for m in mr.markets {
-            match onchain_matches(&chain, dex, &m).await {
-                Ok(true) => markets.push(m),
-                Ok(false) => warn!(chain = n, market = m.id, "on-chain market differs from Odoo; not served"),
+            match onchain_market(&chain, dex, &m).await {
+                Ok(Some((kb, kq))) => {
+                    kinds.insert(m.base, kb);
+                    kinds.insert(m.quote, kq);
+                    markets.push(m);
+                }
+                Ok(None) => warn!(chain = n, market = m.id, "market not listed on the DEX; not served"),
                 Err(e) => warn!(chain = n, market = m.id, "market check: {e:#}; not served"),
             }
         }
@@ -200,11 +229,12 @@ impl Venue {
         let book = Book::load(markets, &load.rows)?;
         info!(chain = n, orders = book.len(), "dex book loaded");
         Ok(Arc::new(Self {
-            domain: domain(n, dex),
             chain,
             relay,
             indexer,
             dex,
+            puller,
+            kinds,
             book: Mutex::new(book),
             trades: Default::default(),
             cancels: Default::default(),
@@ -215,46 +245,89 @@ impl Venue {
         self.chain.address()
     }
 
-    pub fn hash(&self, o: &Order) -> B256 {
-        order_hash(&self.domain, o)
+    fn kind(&self, token: Address) -> u8 {
+        self.kinds.get(&token).copied().unwrap_or_default()
     }
 
     // ------------------------------------------------------------------------------ chain reads
 
-    async fn call(&self, data: Vec<u8>) -> std::result::Result<Bytes, SimError> {
-        let tx = TransactionRequest::default().from(self.relayer()).to(self.dex).input(data.into());
+    async fn call(&self, from: Address, to: Address, data: Vec<u8>) -> std::result::Result<Bytes, SimError> {
+        let tx = TransactionRequest::default().from(from).to(to).input(data.into());
         self.chain.primary().call(tx).await.map_err(|e| classify(&e))
     }
 
-    async fn check(&self, o: &Order, sig: &Bytes) -> Result<ISCaaSDex::checkOrderReturn> {
-        let out = self
-            .call(ISCaaSDex::checkOrderCall { o: o.clone(), sig: sig.clone() }.abi_encode())
-            .await
-            .map_err(|e| anyhow!("checkOrder: {e}"))?;
-        Ok(ISCaaSDex::checkOrderCall::abi_decode_returns(&out)?)
-    }
-
-    /// Simulate `settle`: `Ok(vec ok-per-match)`; mọi cặp fail ⇒ `NothingSettled` ⇒ toàn `false`.
-    async fn simulate(&self, fills: &[PlannedFill]) -> std::result::Result<Vec<bool>, SimError> {
-        let ms = fills.iter().map(PlannedFill::to_match).collect();
-        match self.call(ISCaaSDex::settleCall { ms }.abi_encode()).await {
-            Ok(out) => ISCaaSDex::settleCall::abi_decode_returns(&out)
-                .map_err(|e| SimError::Revert(format!("decode: {e}"))),
-            Err(SimError::Revert(r))
-                if r.contains(&alloy::hex::encode(<ISCaaSDex::NothingSettled as SolError>::SELECTOR)) =>
-            {
-                Ok(vec![false; fills.len()])
+    /// The order's hash where it is checked: the sell token (`TradeOrder`) or the DEX (`DexOrder`).
+    async fn order_hash(&self, sell: Address, o: &TradeOrder) -> Result<B256> {
+        match self.kind(sell) {
+            KIND_SCAAS => view(&self.chain, sell, IToken::tradeOrderDigestCall { o: o.clone() }).await,
+            KIND_OUTSIDE => view(&self.chain, self.dex, ISCaaSDex::dexOrderDigestCall { sellToken: sell, o: o.clone() }).await,
+            _ => bail!("TOKEN_NOT_SERVED: {sell:#x} is not a side of a listed market"),
+        }
+    }
+
+    /// `amount − pulled` (0 when the lane's `minNonce` passed the order) and the signer's deliverable balance.
+    async fn on_chain(&self, sell: Address, h: B256, o: &TradeOrder) -> Result<OnChain> {
+        let outside = self.kind(sell) == KIND_OUTSIDE;
+        let state = if outside { self.dex } else { sell };
+        let (pulled, min) = if outside {
+            (view(&self.chain, state, ISCaaSDex::pulledCall { orderHash: h }).await?,
+             view(&self.chain, state, ISCaaSDex::minNonceCall { from: o.from, batch: o.batch }).await?)
+        } else {
+            (view(&self.chain, state, IToken::pulledCall { orderHash: h }).await?,
+             view(&self.chain, state, IToken::minNonceCall { from: o.from, batch: o.batch }).await?)
+        };
+        let remaining = if o.nonce < min { U256::ZERO } else { o.amount.saturating_sub(pulled) };
+        let mut fundable = view(&self.chain, sell, IToken::balanceOfCall { who: o.from }).await?;
+        if outside {
+            fundable = fundable.min(view(&self.chain, sell, IToken::allowanceCall { owner: o.from, spender: self.puller }).await?);
+        }
+        Ok(OnChain { remaining, fundable })
+    }
+
+    /// A resting order can still settle `r.remaining`: open on chain for that much, funded, signature valid.
+    async fn healthy(&self, r: &Resting) -> Result<bool> {
+        let c = self.on_chain(r.sell, r.hash, &r.order).await?;
+        Ok(c.remaining >= r.remaining && c.fundable >= r.remaining && self.valid_sig(r.order.from, r.hash, &r.sig).await)
+    }
+
+    /// Simulate `mtxSettle` from the lane: `Ok(ok per settlement)`; all failed ⇒ `NothingSettled` ⇒ all `false`. A
+    /// whole-call `SigCheckGasStarved` (CTR-DEX-08) is split and each settlement simulated alone, never retried whole
+    /// with more gas: a party's hook-token destination can forge that selector (P2b-2 H5).
+    async fn simulate(&self, ps: &[PlannedSettlement]) -> std::result::Result<Vec<bool>, SimError> {
+        let s: Vec<_> = ps.iter().map(PlannedSettlement::to_settlement).collect();
+        match self.call(self.relayer(), self.dex, ISCaaSDex::mtxSettleCall { s: s.clone() }.abi_encode()).await {
+            Ok(out) => {
+                ISCaaSDex::mtxSettleCall::abi_decode_returns(&out).map_err(|e| SimError::Revert(format!("decode: {e}")))
+            }
+            Err(SimError::Revert(r)) if r.starts_with("NothingSettled") => Ok(vec![false; ps.len()]),
+            Err(SimError::Revert(r)) if r.starts_with("SigCheckGasStarved") && ps.len() > 1 => {
+                let mut ok = vec![];
+                for p in ps {
+                    ok.push(Box::pin(self.simulate(std::slice::from_ref(p))).await?.first().copied().unwrap_or(false));
+                }
+                Ok(ok)
             }
+            Err(SimError::Revert(r)) if r.starts_with("SigCheckGasStarved") => Ok(vec![false]),
             Err(e) => Err(e),
         }
     }
 
-    /// Chữ ký EOA (khôi phục cục bộ) hoặc ERC-1271 (gọi `isValidSignature` của ví hợp đồng).
+    /// The order a failed settlement blames: its revert data from `settleOne(s, lane)` called as the DEX names an
+    /// order hash (token and DEX errors carry it, NODE-DEX-15); `None` when it names none of them.
+    async fn fault(&self, p: &PlannedSettlement) -> Option<B256> {
+        let data = ISCaaSDex::settleOneCall { s: p.to_settlement(), submitter: self.relayer() }.abi_encode();
+        let tx = TransactionRequest::default().from(self.dex).to(self.dex).input(data.into());
+        let err = self.chain.primary().call(tx).await.err()?;
+        let raw = err.as_error_resp()?.as_revert_data()?;
+        let hashes: Vec<B256> = p.makers.iter().map(|(m, _, _)| m.hash).chain([p.taker.hash]).collect();
+        raw.get(4..)?.chunks_exact(32).map(B256::from_slice).find(|w| hashes.contains(w))
+    }
+
+    /// EOA signature (recovered here, low-s as the contract requires) or ERC-1271 (`isValidSignature`).
     async fn valid_sig(&self, signer: Address, digest: B256, sig: &Bytes) -> bool {
         if sig.len() == 65 {
             if let Ok(s) = Signature::try_from(sig.as_ref()) {
-                // High-s: contract `tryRecover` từ chối ⇒ `cancel` bỏ qua im lặng (review I4). Không trả
-                // false ngay: ví hợp đồng vẫn đi ERC-1271 như contract (phân biệt bằng code, không độ dài).
+                // High-s: `ECDSA.tryRecover` refuses it (review I4). A contract wallet still goes the ERC-1271 way.
                 if s.normalize_s().is_none() && s.recover_address_from_prehash(&digest).ok() == Some(signer) {
                     return true;
                 }
@@ -273,94 +346,99 @@ impl Venue {
 
     // ------------------------------------------------------------------------------ intake
 
-    pub async fn place(&self, wire: &WireOrder, signature: &str) -> std::result::Result<PlaceReply, VenueError> {
+    /// `POST /v1/dex/orders {chain, sellToken, order, signature}`: the order is a `TradeOrder` for a SCaaS sell token
+    /// and a `DexOrder` for an outside one, by the DEX's listing.
+    pub async fn place(&self, sell: Address, wire: &WireOrder, signature: &str) -> std::result::Result<PlaceReply, VenueError> {
         let o = wire.to_sol().map_err(bad)?;
         let sig = sig_bytes(signature)?;
-        let h = self.hash(&o);
-        let c = self.check(&o, &sig).await.map_err(down)?;
-        if c.h != h {
-            // KAT lệch giữa node và contract: không bao giờ nhận lệnh mà chain băm khác.
-            return Err(down(format!("order hash mismatch: node {h:#x}, chain {:#x}", c.h)));
+        if self.kind(sell) == 0 {
+            return Err(bad(format!("TOKEN_NOT_SERVED: {sell:#x} is not a side of a listed market")));
         }
-        if c.status != ST_OK {
-            return Err(bad(format!("order refused on-chain: {}", status_name(c.status))));
+        let h = self.order_hash(sell, &o).await.map_err(down)?;
+        if !self.valid_sig(o.from, h, &sig).await {
+            return Err(bad("bad order signature"));
         }
+        let c = self.on_chain(sell, h, &o).await.map_err(down)?;
         let mut book = self.book.lock().await;
         book.purge(now());
-        book.admit(h, &o, c.remaining, c.fundable, c.feeFundable, self.relayer(), now()).map_err(bad)?;
+        book.admit(h, sell, &o, c.remaining, c.fundable, self.relayer(), self.dex, now()).map_err(bad)?;
 
         let mut commit = Commit::default();
         let mut dropped_makers: Vec<B256> = vec![];
-        let mut trial;
-        let mut placed;
+        let (mut trial, mut placed);
         let mut round = 0;
         loop {
             trial = book.clone();
             for d in &dropped_makers {
                 trial.remove(*d);
             }
-            placed = trial.place(h, o.clone(), sig.clone(), c.remaining);
-            if placed.fills.is_empty() {
-                break;
-            }
-            let ok = self.simulate(&placed.fills).await.map_err(|e| match e {
+            placed = trial.place(h, sell, o.clone(), sig.clone(), c.remaining);
+            let Some(s) = &placed.settlement else { break };
+            let ok = self.simulate(std::slice::from_ref(s)).await.map_err(|e| match e {
                 SimError::Revert(r) => bad(format!("settlement simulation: {r}")),
                 SimError::Transport(r) => down(format!("rpc: {r}")),
             })?;
-            let failed: Vec<&PlannedFill> = placed.fills.iter().zip(&ok).filter(|(_, ok)| !**ok).map(|(f, _)| f).collect();
-            if failed.is_empty() {
+            if ok.first() == Some(&true) {
                 break;
             }
-            round += 1;
-            for f in failed {
-                let m = &f.maker;
-                let healthy = match self.check(&m.order, &m.sig).await {
-                    Ok(mc) => funded(&m.order, m.remaining, &mc),
-                    Err(e) => return Err(down(e)),
-                };
-                if healthy {
-                    // Lệnh nghỉ còn tốt mà cặp vẫn fail ⇒ lỗi nằm ở lệnh mới.
-                    return Err(bad("settlement simulation refused this order"));
+            // NODE-DEX-02: blame by evidence. An order hash in the revert names the order at fault; otherwise each
+            // maker's state is read, and a maker that can no longer settle is the one dropped.
+            let at_fault = match self.fault(s).await {
+                Some(f) if f == h => return Err(bad("settlement simulation refused this order")),
+                Some(f) => vec![f],
+                None => {
+                    let mut v = vec![];
+                    for (m, _, _) in &s.makers {
+                        if !self.healthy(m).await.map_err(down)? {
+                            v.push(m.hash);
+                        }
+                    }
+                    v
                 }
-                if let Some(mk) = book.market(&m.order) {
-                    commit.order(mk.id, m, "invalid");
+            };
+            if at_fault.is_empty() {
+                return Err(bad("settlement simulation refused this order"));
+            }
+            for f in at_fault {
+                if let Some((m, _, _)) = s.makers.iter().find(|(m, _, _)| m.hash == f) {
+                    commit.order(s.market_id, m, "invalid");
                 }
-                dropped_makers.push(m.hash);
+                dropped_makers.push(f);
             }
+            round += 1;
             if round >= MAX_ROUNDS {
                 return Err(down("order book unstable; retry"));
             }
         }
 
-        let (market_id, base) = book.market(&o).map(|m| (m.id, m.base)).ok_or_else(|| bad("no market"))?;
-        self.add_fills(&mut commit, &trial, &placed.fills);
-        let filled_here: U256 = placed.fills.iter().map(|f| f.taker_fill).sum();
-        let taker_after = Resting {
-            hash: h,
-            order: o.clone(),
-            sig: sig.clone(),
-            remaining: c.remaining - filled_here,
-            seq: placed.seq,
-        };
+        let (market_id, base) =
+            book.market_of(sell, o.receiveToken).map(|m| (m.id, m.base)).ok_or_else(|| bad("no market"))?;
+        for d in &placed.dust {
+            commit.order(market_id, &Resting { remaining: U256::ZERO, ..d.clone() }, "filled");
+        }
+        let settlement: Vec<PlannedSettlement> = placed.settlement.iter().cloned().collect();
+        self.add_settlements(&mut commit, &trial, &settlement);
+        let filled_here = placed.settlement.as_ref().map(|s| s.taker_fill).unwrap_or_default();
+        let taker_after = Resting { hash: h, sell, order: o.clone(), sig: sig.clone(), remaining: c.remaining - filled_here, seq: placed.seq };
         let taker_state = match (&placed.rested, placed.dropped.is_zero()) {
             (Some(_), _) => state_of(&taker_after),
             (None, true) => "filled",
-            (None, false) => "cancelled", // IOC/FOK: phần còn lại huỷ, không nghỉ
+            (None, false) => "cancelled", // IOC, or a remainder that would rest crossed
         };
         commit.order(market_id, &taker_after, taker_state);
         self.commit_or_reload(&mut book, trial, commit).await?;
         drop(book);
 
         let fills: Vec<Value> = placed
-            .fills
+            .settlement
             .iter()
-            .map(|f| {
-                json!({"tag": format!("{:#x}", f.tag), "maker_hash": format!("{:#x}", f.maker.hash),
-                       "maker_fill": f.maker_fill.to_string(), "taker_fill": f.taker_fill.to_string()})
-            })
+            .flat_map(|s| s.makers.iter().map(move |(m, x, y)| {
+                json!({"tag": format!("{:#x}", s.tag), "maker_hash": format!("{:#x}", m.hash),
+                       "maker_fill": x.to_string(), "taker_fill": y.to_string()})
+            }))
             .collect();
-        self.remember(&placed.fills, base);
-        let status = match (placed.rested.is_some(), placed.fills.is_empty(), placed.dropped.is_zero()) {
+        self.remember(&settlement, base);
+        let status = match (placed.rested.is_some(), placed.settlement.is_none(), placed.dropped.is_zero()) {
             (true, true, _) => "resting",
             (true, false, _) => "partial",
             (false, _, true) => "filled",
@@ -374,26 +452,24 @@ impl Venue {
         })
     }
 
-    /// Lệnh maker sau khớp + trade + một job `settle` mỗi thị trường (nguyên tử từng cặp on-chain).
-    fn add_fills(&self, commit: &mut Commit, after: &Book, fills: &[PlannedFill]) {
-        for f in fills {
-            let mk = after.get(f.maker.hash).cloned().unwrap_or_else(|| Resting { remaining: U256::ZERO, ..f.maker.clone() });
-            commit.order(f.market_id, &mk, state_of(&mk));
+    /// The makers after matching, one trade per settlement, and one `mtxSettle` job per market.
+    fn add_settlements(&self, commit: &mut Commit, after: &Book, ss: &[PlannedSettlement]) {
+        for s in ss {
+            for (m, _, _) in &s.makers {
+                let now_m = after.get(m.hash).cloned().unwrap_or_else(|| Resting { remaining: U256::ZERO, ..m.clone() });
+                commit.order(s.market_id, &now_m, state_of(&now_m));
+            }
             commit.trades.push(json!({
-                "tag": format!("{:#x}", f.tag), "market_id": f.market_id,
-                "maker_hash": format!("{:#x}", f.maker.hash), "taker_hash": format!("{:#x}", f.taker.hash),
-                "maker_fill": f.maker_fill.to_string(), "taker_fill": f.taker_fill.to_string(),
+                "tag": format!("{:#x}", s.tag), "market_id": s.market_id,
+                "taker_hash": format!("{:#x}", s.taker.hash), "taker_fill": s.taker_fill.to_string(),
+                "makers": s.makers.iter().map(|(m, x, _)| json!({"hash": format!("{:#x}", m.hash), "fill": x.to_string()}))
+                    .collect::<Vec<_>>(),
             }));
         }
-        commit.jobs.extend(settle_jobs(self.dex, fills));
+        commit.jobs.extend(settle_jobs(self.dex, ss));
     }
 
-    async fn commit_or_reload(
-        &self,
-        book: &mut Book,
-        next: Book,
-        commit: Commit,
-    ) -> std::result::Result<(), VenueError> {
+    async fn commit_or_reload(&self, book: &mut Book, next: Book, commit: Commit) -> std::result::Result<(), VenueError> {
         if commit.is_empty() {
             *book = next;
             return Ok(());
@@ -406,8 +482,8 @@ impl Venue {
                 Ok(())
             }
             Err(e) => {
-                // Timeout có thể là "Odoo đã commit": không đoán, nạp lại sự thật (review D20).
-                warn!(chain = self.chain.number, "dex_book_commit: {e:#}; reloading the book from Odoo");
+                // A timeout may be "the client committed": never guess, reload the truth (review D20).
+                warn!(chain = self.chain.number, "dex_book_commit: {e:#}; reloading the book from the client");
                 if let Err(e2) = self.reload(book).await {
                     warn!(chain = self.chain.number, "reload: {e2:#}");
                 }
@@ -423,139 +499,166 @@ impl Venue {
         Ok(())
     }
 
-    fn remember(&self, fills: &[PlannedFill], base: Address) {
+    fn remember(&self, ss: &[PlannedSettlement], base: Address) {
         let Ok(mut t) = self.trades.lock() else { return };
-        for f in fills {
-            t.push_front(trade_view(f, base, now()));
+        for s in ss {
+            t.push_front(trade_view(s, base, now()));
             t.truncate(RECENT_TRADES);
         }
     }
 
     // ------------------------------------------------------------------------------ cancel
 
-    /// Huỷ một lệnh bằng chữ ký `CancelOrder(orderHash)`: gỡ khỏi sổ NGAY + xếp huỷ on-chain.
+    /// Cancel one order with a `CancelOrder(orderHash)` signature (the sell token's domain, or the DEX's for an
+    /// outside token): out of the book NOW, then closed on chain at the next sync.
     pub async fn cancel(&self, h: B256, signature: &str) -> std::result::Result<(), VenueError> {
         let sig = sig_bytes(signature)?;
         let mut book = self.book.lock().await;
         let r = book.get(h).cloned().ok_or_else(|| bad("order is not in the book"))?;
-        if !self.valid_sig(r.order.maker, cancel_digest(&self.domain, h), &sig).await {
+        let kind = self.kind(r.sell);
+        let digest = match kind {
+            KIND_SCAAS => view(&self.chain, r.sell, IToken::cancelOrderDigestCall { orderHash: h }).await,
+            _ => view(&self.chain, self.dex, ISCaaSDex::cancelOrderDigestCall { orderHash: h }).await,
+        }
+        .map_err(down)?;
+        if !self.valid_sig(r.order.from, digest, &sig).await {
             return Err(bad("bad cancel signature"));
         }
-        let market_id = book.market(&r.order).map(|m| m.id).unwrap_or_default();
+        let market_id = book.market_of(r.sell, r.order.receiveToken).map(|m| m.id).unwrap_or_default();
         let mut next = book.clone();
         next.remove(h);
         let mut commit = Commit::default();
         commit.order(market_id, &r, "cancelled");
         self.commit_or_reload(&mut book, next, commit).await?;
         if let Ok(mut q) = self.cancels.lock() {
-            if q.allow(r.order.maker, now()) {
-                q.pending.push((market_id, CancelReq { order: r.order, sig }));
+            if q.allow(r.order.from, now()) {
+                q.pending.push((market_id, r.sell, kind, r.order, sig));
             }
         }
         Ok(())
     }
 
-    /// Huỷ-hết: `InvalidateNonces(maker, minNonce)`. Chỉ khi maker còn ≥ 1 lệnh mở (chặn spam gas).
-    pub async fn cancel_all(&self, maker: Address, min: U256, signature: &str) -> std::result::Result<usize, VenueError> {
+    /// Cancel-all of a lane: `InvalidateNonces(from, batch, minNonce)` in the sell token's domain (its SCaaS orders)
+    /// or the DEX's (every outside-token order). Only while the signer has an open order there (gas spam).
+    pub async fn cancel_all(&self, sell: Address, from: Address, batch: U256, min: U256, signature: &str)
+        -> std::result::Result<usize, VenueError>
+    {
         let sig = sig_bytes(signature)?;
+        let kind = self.kind(sell);
+        let outside = kind == KIND_OUTSIDE;
+        let in_scope = |s: Address| if outside { self.kind(s) == KIND_OUTSIDE } else { s == sell };
         let mut book = self.book.lock().await;
-        let open = book.open_of(maker);
-        let Some(first) = open.first() else { return Err(bad("maker has no open orders")) };
-        let market_id = book.market(&first.order).map(|m| m.id).unwrap_or_default();
-        if !self.valid_sig(maker, invalidate_digest(&self.domain, maker, min), &sig).await {
+        let open: Vec<Resting> = book.open_of(from).into_iter().filter(|r| r.order.batch == batch && in_scope(r.sell)).cloned().collect();
+        let Some(first) = open.first() else { return Err(bad("no open order of this signer on that lane")) };
+        let market_id = book.market_of(first.sell, first.order.receiveToken).map(|m| m.id).unwrap_or_default();
+        let (target, digest, call) = if outside {
+            (self.dex, view(&self.chain, self.dex, ISCaaSDex::invalidateNoncesDigestCall { from, batch, newMin: min }).await,
+             ISCaaSDex::mtxInvalidateNoncesCall { from, batch, newMin: min, sig: sig.clone() }.abi_encode())
+        } else {
+            (sell, view(&self.chain, sell, IToken::invalidateNoncesDigestCall { from, batch, newMin: min }).await,
+             IToken::mtxInvalidateNoncesCall { from, batch, newMin: min, sig: sig.clone() }.abi_encode())
+        };
+        if !self.valid_sig(from, digest.map_err(down)?, &sig).await {
             return Err(bad("bad invalidate signature"));
         }
-        let call = ISCaaSDex::invalidateNoncesCall { maker, newMin: min, sig: sig.clone() }.abi_encode();
-        if let Err(e) = self.call(call.clone()).await {
-            return Err(bad(format!("invalidateNonces refused: {e}")));
-        }
+        // already at or past `min` on chain (MinNonceNotIncreasing): the orders are closed, no job needed
+        let job_needed = match self.call(self.relayer(), target, call.clone()).await {
+            Ok(_) => true,
+            Err(SimError::Revert(r)) if r.starts_with("MinNonceNotIncreasing(") => false,
+            Err(e) => return Err(bad(format!("mtxInvalidateNonces refused: {e}"))),
+        };
         let mut next = book.clone();
+        let gone = next.drop_below(from, batch, min, &in_scope);
         let mut commit = Commit::default();
-        for r in book.open_of(maker).into_iter().filter(|r| r.order.nonce < min) {
-            commit.order(book.market(&r.order).map(|m| m.id).unwrap_or_default(), r, "cancelled");
-        }
-        let n = next.drop_below(maker, min).len();
-        let allowed = self.cancels.lock().map(|mut q| q.allow(maker, now())).unwrap_or(false);
-        if allowed {
-            commit.jobs.push(json!({
-                "kind": "invalidate", "market_id": market_id, "target": format!("{:#x}", self.dex),
-                "calldata": hex_of(&call), "valid_until": (now() + 86_400).to_string(), "tags": [],
-            }));
+        for r in &gone {
+            commit.order(book.market_of(r.sell, r.order.receiveToken).map(|m| m.id).unwrap_or_default(), r, "cancelled");
+        }
+        let allowed = self.cancels.lock().map(|mut q| q.allow(from, now())).unwrap_or(false);
+        if job_needed && allowed {
+            let valid_until = (now() + CANCEL_JOB_SECS).to_string();
+            commit.jobs.push(if outside {
+                json!({"kind": "invalidate", "market_id": market_id, "target": format!("{:#x}", self.dex),
+                       "calldata": hex_of(&call), "valid_until": valid_until, "tags": []})
+            } else {
+                json!({"kind": "metatx", "entry": "mtxInvalidateNonces", "market_id": market_id,
+                       "token": format!("{sell:#x}"), "from": format!("{from:#x}"), "batch": batch.to_string(),
+                       "newMin": min.to_string(), "signature": hex_of(&sig), "validUntil": valid_until})
+            });
         }
         self.commit_or_reload(&mut book, next, commit).await?;
-        Ok(n)
+        Ok(gone.len())
     }
 
     // ------------------------------------------------------------------------------ loops
 
-    /// Trade fail ⇒ trả lại sổ; huỷ chờ ⇒ một tx `cancel`; hết hạn ⇒ bỏ khỏi bộ nhớ.
+    /// Failed trades back to the book; pending cancels to the chain; expired orders out of memory.
     pub async fn sync_once(&self) -> Result<()> {
         let sr: SyncReply =
             self.relay.call("blockchain.dex.trade", "dex_sync", json!({"evm_chain_number": self.chain.number})).await?;
         let mut book = self.book.lock().await;
         book.purge(now());
         let mut commit = Commit::default();
-        // Khớp lại; cặp không simulate được ⇒ hai bên của nó không được trả về trong vòng này
-        // (vẫn ack): không bao giờ kẹt cả chain vì một lệnh hỏng (review I3).
-        // ponytail: bỏ cả bên khoẻ của cặp hỏng; đo trước khi tách từng bên.
+        // Match again; a settlement that does not simulate leaves its orders out of this round (still acked): one bad
+        // order never jams the chain (review I3). ponytail: drops the healthy legs of a bad settlement too; split
+        // per leg if that ever costs real fills.
         let mut skip: Vec<B256> = vec![];
-        let (mut next, mut fills, mut touched);
+        let (mut next, mut settlements, mut touched);
         let (mut round, mut give_up) = (0, false);
         loop {
             next = book.clone();
-            fills = Vec::<PlannedFill>::new();
+            settlements = Vec::<PlannedSettlement>::new();
             touched = Vec::<(i64, Resting)>::new();
             for ft in &sr.failed {
-                for (row, fill) in [(&ft.maker, &ft.maker_fill), (&ft.taker, &ft.taker_fill)] {
-                    let Some(row) = row else { continue };
+                // makers first: each goes back as it rested, then the taker takes again in its original role
+                for leg in ft.makers.iter().chain(std::iter::once(&ft.taker)) {
+                    let Some(row) = &leg.row else { continue };
                     let r = row.resting()?;
-                    let fill = crate::metatx::uint(fill)?;
-                    if give_up
-                        || skip.contains(&r.hash)
-                        || r.order.flags & (FLAG_IOC | FLAG_FOK) != 0
-                        || r.order.expiry < U256::from(now())
-                    {
+                    let fill = crate::metatx::uint(&leg.fill)?;
+                    if give_up || skip.contains(&r.hash) || r.order.flags & FLAG_IOC != 0 || r.order.validUntil < U256::from(now()) {
                         continue;
                     }
+                    let Some(market_id) = next.market_of(r.sell, r.order.receiveToken).map(|m| m.id) else { continue };
                     let in_book = next.get(r.hash).map(|x| x.remaining).unwrap_or_default();
-                    let c = self.check(&r.order, &r.sig).await?;
+                    let c = self.on_chain(r.sell, r.hash, &r.order).await?;
                     let add = fill.min(c.remaining.saturating_sub(in_book));
-                    let Some(market_id) = next.market(&r.order).map(|m| m.id) else { continue };
-                    if add.is_zero() || !funded(&r.order, in_book + add, &c) {
+                    if add.is_zero() || c.fundable < in_book + add {
                         continue;
                     }
-                    // Đi lại qua matcher: hai bên cùng khoẻ thì khớp lại, không để sổ chéo.
-                    fills.extend(next.restore(r.clone(), add).fills);
+                    // Through the matcher: two healthy sides trade again, never a crossed book.
+                    settlements.extend(next.restore(r.clone(), add).settlement);
                     touched.push((market_id, r));
                 }
             }
-            if fills.is_empty() {
+            if settlements.is_empty() {
                 break;
             }
-            let ok = self.simulate(&fills).await.map_err(|e| anyhow!("re-match simulation: {e}"))?;
-            let bad: Vec<B256> =
-                fills.iter().zip(&ok).filter(|(_, ok)| !**ok).flat_map(|(f, _)| [f.maker.hash, f.taker.hash]).collect();
-            if bad.is_empty() {
+            let ok = self.simulate(&settlements).await.map_err(|e| anyhow!("re-match simulation: {e}"))?;
+            let failed: Vec<B256> = settlements
+                .iter()
+                .zip(&ok)
+                .filter(|(_, ok)| !**ok)
+                .flat_map(|(s, _)| s.makers.iter().map(|(m, _, _)| m.hash).chain([s.taker.hash]))
+                .collect();
+            if failed.is_empty() {
                 break;
             }
-            warn!(chain = self.chain.number, n = bad.len() / 2, "re-matched fills do not simulate; not restoring them");
-            skip.extend(bad);
+            warn!(chain = self.chain.number, n = failed.len(), "re-matched settlements do not simulate; not restoring them");
+            skip.extend(failed);
             round += 1;
-            give_up = round >= MAX_ROUNDS; // vòng cuối không trả gì về: ack, không kẹt
+            give_up = round >= MAX_ROUNDS; // the last round hands nothing back: ack, never jam
         }
         commit.acks.extend(sr.failed.iter().map(|ft| ft.tag.clone()));
-        self.add_fills(&mut commit, &next, &fills);
-        // Mọi lệnh trả về sổ (kể cả không khớp lại) phải ghi xuống Odoo, nếu không restart sẽ mất nó.
+        self.add_settlements(&mut commit, &next, &settlements);
+        // Every order handed back (re-matched or not) is written to the client, or a restart loses it.
         for (market_id, r) in &touched {
             let now_r = next.get(r.hash).cloned().unwrap_or_else(|| Resting { remaining: U256::ZERO, ..r.clone() });
             commit.order(*market_id, &now_r, state_of(&now_r));
         }
-        let pending: Vec<(i64, CancelReq)> =
-            self.cancels.lock().map(|mut q| std::mem::take(&mut q.pending)).unwrap_or_default();
+        let pending: Vec<PendingCancel> = self.cancels.lock().map(|mut q| std::mem::take(&mut q.pending)).unwrap_or_default();
         commit.jobs.extend(cancel_jobs(self.dex, &pending));
         let res = self.commit_or_reload(&mut book, next, commit).await;
         if res.is_err() && !pending.is_empty() {
-            // Không mất huỷ on-chain khi Odoo lỗi; gửi trùng thì `origin_key` + `cancel` no-op chặn.
+            // Never lose an on-chain cancel when the client store fails; a duplicate is a no-op on chain.
             if let Ok(mut q) = self.cancels.lock() {
                 q.pending.extend(pending);
             }
@@ -563,8 +666,8 @@ impl Venue {
         res.map_err(|e| anyhow!("{e}"))
     }
 
-    /// Một vòng watcher: log DEX trong vùng final ⇒ `dex_fill_ingest` ⇒ gỡ lệnh bị đóng on-chain.
-    /// `true` = đã tiến.
+    /// One watcher round: the DEX's and the market tokens' logs in the final range ⇒ `dex_fill_ingest` ⇒ orders
+    /// closed on chain leave the book. `true` = progressed.
     pub async fn watch_once(&self) -> Result<bool> {
         let Some(idx) = &self.indexer else { return Ok(false) };
         let nc = idx.node_config(self.chain.number, None).await?;
@@ -583,7 +686,14 @@ impl Venue {
         if !quorum_ok(hash, &others, nc.finality_quorum) {
             return Ok(false);
         }
-        let f = Filter::new().from_block(from).to_block(to).address(self.dex);
+        let mut contracts: Vec<Address> = self.kinds.keys().copied().collect();
+        contracts.push(self.dex);
+        let f = Filter::new().from_block(from).to_block(to).address(contracts).event_signature(vec![
+            ISCaaSDex::LegSettled::SIGNATURE_HASH,
+            ISCaaSDex::MatchFailed::SIGNATURE_HASH,
+            ISCaaSDex::OrderCancelled::SIGNATURE_HASH,
+            ISCaaSDex::NoncesInvalidated::SIGNATURE_HASH,
+        ]);
         let logs = self.chain.primary().get_logs(&f).await?;
         let events: Vec<Value> = logs.iter().filter_map(encode_event).collect();
         let _: Value = idx
@@ -594,9 +704,10 @@ impl Venue {
                        "to_block_hash": format!("{hash:#x}"), "events": events}),
             )
             .await?;
-        // Odoo đã đánh dấu lệnh đóng; sổ trong bộ nhớ theo sau (review D13).
+        // The client closed the orders; the book in memory follows (review D13).
         let mut book = self.book.lock().await;
         for e in &events {
+            let addr_of = |k: &str| e[k].as_str().unwrap_or_default().parse::<Address>();
             match e["event"].as_str() {
                 Some("OrderCancelled") => {
                     if let Ok(h) = e["order_hash"].as_str().unwrap_or_default().parse::<B256>() {
@@ -604,11 +715,14 @@ impl Venue {
                     }
                 }
                 Some("NoncesInvalidated") => {
-                    if let (Ok(m), Ok(n)) = (
-                        e["maker"].as_str().unwrap_or_default().parse::<Address>(),
+                    if let (Ok(c), Ok(from), Ok(batch), Ok(min)) = (
+                        addr_of("contract"),
+                        addr_of("from"),
+                        crate::metatx::uint(e["batch"].as_str().unwrap_or_default()),
                         crate::metatx::uint(e["min_nonce"].as_str().unwrap_or_default()),
                     ) {
-                        book.drop_below(m, n);
+                        let dex_lane = c == self.dex;
+                        book.drop_below(from, batch, min, &|s| if dex_lane { self.kind(s) == KIND_OUTSIDE } else { s == c });
                     }
                 }
                 _ => {}
@@ -667,31 +781,48 @@ impl Venue {
         }))
     }
 
-    pub async fn orders_of(&self, maker: Address) -> Vec<Value> {
+    pub async fn orders_of(&self, from: Address) -> Vec<Value> {
         let book = self.book.lock().await;
-        book.open_of(maker)
+        book.open_of(from)
             .into_iter()
             .map(|r| {
-                json!({"order_hash": format!("{:#x}", r.hash), "order": WireOrder::from_sol(&r.order),
-                       "remaining": r.remaining.to_string(), "state": state_of(r)})
+                json!({"order_hash": format!("{:#x}", r.hash), "sell_token": format!("{:#x}", r.sell),
+                       "order": WireOrder::from_sol(&r.order), "remaining": r.remaining.to_string(), "state": state_of(r)})
             })
             .collect()
     }
 
-    /// Test/vận hành: hàng sổ hiện tại.
+    /// Tests and operations: the book's rows now.
     pub async fn rows(&self) -> Vec<Row> {
         self.book.lock().await.rows()
     }
 }
 
-/// Một dòng trên băng giao dịch: giá quote/base, lượng base, phía của taker.
-/// Không suy phía từ cặp lệnh: maker luôn bán đúng thứ taker mua, nên chỉ `base` của thị trường phân biệt.
-fn trade_view(f: &PlannedFill, base: Address, at: u64) -> TradeView {
-    let taker_buys_base = f.taker.order.buyToken == base;
-    let (quote, base_amt) = if taker_buys_base { (f.taker_fill, f.maker_fill) } else { (f.maker_fill, f.taker_fill) };
+async fn view<C: SolCall>(chain: &Chain, to: Address, call: C) -> Result<C::Return> {
+    let tx = TransactionRequest::default().to(to).input(call.abi_encode().into());
+    Ok(C::abi_decode_returns(&chain.primary().call(tx).await?)?)
+}
+
+/// The market as the DEX lists it: `Some((kind of base, kind of quote))` when listed and both classified.
+async fn onchain_market(chain: &Chain, dex: Address, m: &MarketCfg) -> Result<Option<(u8, u8)>> {
+    let (a, b) = pair(m.base, m.quote);
+    if !view(chain, dex, ISCaaSDex::marketListedCall { a, b }).await? {
+        return Ok(None);
+    }
+    let kb = view(chain, dex, ISCaaSDex::tokenKindCall { token: m.base }).await?;
+    let kq = view(chain, dex, ISCaaSDex::tokenKindCall { token: m.quote }).await?;
+    Ok((kb != 0 && kq != 0).then_some((kb, kq)))
+}
+
+/// One line on the tape: quote/base price, base amount, the taker's side. The side is read from the market's base:
+/// the makers sell exactly what the taker buys.
+fn trade_view(s: &PlannedSettlement, base: Address, at: u64) -> TradeView {
+    let taker_buys_base = s.taker.order.receiveToken == base;
+    let (quote, base_amt) =
+        if taker_buys_base { (s.taker_fill, s.taker_receives()) } else { (s.taker_receives(), s.taker_fill) };
     TradeView {
-        market_id: f.market_id,
-        tag: format!("{:#x}", f.tag),
+        market_id: s.market_id,
+        tag: format!("{:#x}", s.tag),
         price: format!("{quote}/{base_amt}"),
         base_amount: base_amt.to_string(),
         taker_side: if taker_buys_base { "buy" } else { "sell" },
@@ -699,46 +830,55 @@ fn trade_view(f: &PlannedFill, base: Address, at: u64) -> TradeView {
     }
 }
 
-/// Thứ tự id thị trường, giữ thứ tự trong mỗi thị trường (sort ổn định).
+/// By market id, keeping the order inside each market (stable sort).
 fn by_market<T: Clone>(items: &[T], market: impl Fn(&T) -> i64) -> Vec<Vec<T>> {
     let mut v = items.to_vec();
     v.sort_by_key(&market);
     v.chunk_by(|a, b| market(a) == market(b)).map(<[T]>::to_vec).collect()
 }
 
-/// Một job mỗi thị trường: Odoo gắn job vào company của thị trường (review agy F3 — lô sync trộn
-/// nhiều thị trường từng gắn trade của company B vào job của company A).
-fn settle_jobs(dex: Address, fills: &[PlannedFill]) -> Vec<Value> {
-    by_market(fills, |f| f.market_id)
+/// One `mtxSettle` job per market: the client attaches a job to its market's company (review agy F3).
+fn settle_jobs(dex: Address, ss: &[PlannedSettlement]) -> Vec<Value> {
+    by_market(ss, |s| s.market_id)
         .into_iter()
-        .map(|fills| {
-            let ms = fills.iter().map(PlannedFill::to_match).collect();
-            let valid_until =
-                fills.iter().flat_map(|f| [f.maker.order.expiry, f.taker.order.expiry]).min().unwrap_or_default();
+        .map(|ss| {
+            let s = ss.iter().map(PlannedSettlement::to_settlement).collect();
+            let valid_until = ss.iter().map(PlannedSettlement::valid_until).min().unwrap_or_default();
             json!({
-                "kind": "settle", "market_id": fills[0].market_id, "target": format!("{dex:#x}"),
-                "calldata": hex_of(&ISCaaSDex::settleCall { ms }.abi_encode()),
+                "kind": "settle", "market_id": ss[0].market_id, "target": format!("{dex:#x}"),
+                "calldata": hex_of(&ISCaaSDex::mtxSettleCall { s }.abi_encode()),
                 "valid_until": valid_until.to_string(),
-                "tags": fills.iter().map(|f| format!("{:#x}", f.tag)).collect::<Vec<_>>(),
+                "tags": ss.iter().map(|s| format!("{:#x}", s.tag)).collect::<Vec<_>>(),
             })
         })
         .collect()
 }
 
-fn cancel_jobs(dex: Address, pending: &[(i64, CancelReq)]) -> Vec<Value> {
-    by_market(pending, |p| p.0)
+/// SCaaS-token orders: one `mtxCancelOrder` entry job each, on the sell token. Outside-token orders: one
+/// `mtxCancelOrders` call on the DEX per market, at most `CANCEL_BATCH` orders.
+fn cancel_jobs(dex: Address, pending: &[PendingCancel]) -> Vec<Value> {
+    let valid_until = (now() + CANCEL_JOB_SECS).to_string();
+    let mut jobs: Vec<Value> = pending
         .iter()
-        .flat_map(|m| m.chunks(CANCEL_BATCH))
-        .map(|chunk| {
-            let reqs: Vec<CancelReq> = chunk.iter().map(|(_, r)| r.clone()).collect();
-            let valid_until = reqs.iter().map(|r| r.order.expiry).max().unwrap_or_default();
-            json!({
-                "kind": "cancel", "market_id": chunk[0].0, "target": format!("{dex:#x}"),
-                "calldata": hex_of(&ISCaaSDex::cancelCall { reqs }.abi_encode()),
-                "valid_until": valid_until.to_string(), "tags": [],
-            })
+        .filter(|p| p.2 == KIND_SCAAS)
+        .map(|(m, sell, _, o, sig)| {
+            json!({"kind": "metatx", "entry": "mtxCancelOrder", "market_id": m, "token": format!("{sell:#x}"),
+                   "order": WireOrder::from_sol(o), "signature": hex_of(sig), "validUntil": valid_until})
         })
-        .collect()
+        .collect();
+    let outside: Vec<PendingCancel> = pending.iter().filter(|p| p.2 != KIND_SCAAS).cloned().collect();
+    for m in by_market(&outside, |p| p.0) {
+        for chunk in m.chunks(CANCEL_BATCH) {
+            let orders = chunk.iter().map(|(_, s, _, o, _)| DexOrder { sellToken: *s, order: o.clone() }).collect();
+            let sigs = chunk.iter().map(|p| p.4.clone()).collect();
+            jobs.push(json!({
+                "kind": "cancel", "market_id": chunk[0].0, "target": format!("{dex:#x}"),
+                "calldata": hex_of(&ISCaaSDex::mtxCancelOrdersCall { orders, sigs }.abi_encode()),
+                "valid_until": valid_until, "tags": [],
+            }));
+        }
+    }
+    jobs
 }
 
 fn sig_bytes(s: &str) -> std::result::Result<Bytes, VenueError> {
@@ -749,47 +889,16 @@ fn sig_bytes(s: &str) -> std::result::Result<Bytes, VenueError> {
     Ok(b)
 }
 
-fn status_name(s: u8) -> &'static str {
-    ["ok", "bad flags", "expired", "nonce invalidated", "bad signature", "closed", "market not listed", "bad fee"]
-        .get(usize::from(s))
-        .copied()
-        .unwrap_or("unknown")
-}
-
-/// Thị trường Odoo khớp on-chain (niêm yết, cờ phí, ppm, người nhận phí).
-async fn onchain_matches(chain: &Chain, dex: Address, m: &MarketCfg) -> Result<bool> {
-    let (a, b) = pair(m.base, m.quote);
-    let key_call = ISCaaSDex::marketKeyCall { a, b }.abi_encode();
-    let tx = TransactionRequest::default().to(dex).input(key_call.into());
-    let key = B256::from_slice(&chain.primary().call(tx).await?[..32]);
-    let tx = TransactionRequest::default().to(dex).input(ISCaaSDex::marketsCall { key }.abi_encode().into());
-    let out = chain.primary().call(tx).await?;
-    let r = ISCaaSDex::marketsCall::abi_decode_returns(&out)?;
-    let fees_ok = if r.feeOn {
-        m.fee_on && r.makerFeePpm == m.maker_fee_ppm && r.takerFeePpm == m.taker_fee_ppm && r.feeRecipient == m.fee_recipient
-    } else {
-        !m.fee_on
-    };
-    Ok(r.listed && fees_ok)
-}
-
-/// Tên lỗi DEX đọc được (cho `MatchFailed.reason` ở Odoo); không nhận ra ⇒ bộ giải mã chung.
+/// Readable DEX error (for `MatchFailed.reason` in the client); an EMPTY reason is the settlement's self-call
+/// running out of gas, never an order's fault (P2b-2: success is not monotonic in gas).
 pub fn revert_name(data: &[u8]) -> String {
-    match ISCaaSDex::ISCaaSDexErrors::abi_decode(data) {
-        Ok(e) => format!("{e:?}"),
-        Err(_) => crate::abi::decode_revert(data),
+    if data.is_empty() {
+        return "out_of_gas".into();
     }
+    crate::abi::decode_revert(data)
 }
 
-/// Lệnh nghỉ còn settle được `remaining`: OK on-chain và đủ số dư/allowance kể cả phí relayer
-/// (review I2/I3: thiếu 1 wei phí cũng làm mọi cặp với nó fail).
-fn funded(o: &Order, remaining: U256, c: &ISCaaSDex::checkOrderReturn) -> bool {
-    let (ft, fee) = relayer_fee(o, remaining);
-    let own = if ft == o.sellToken { fee } else { U256::ZERO };
-    c.status == ST_OK && c.fundable >= remaining + own && (ft == o.sellToken || c.feeFundable >= fee)
-}
-
-/// Log DEX ⇒ JSON đúng khoá `dex_fill_ingest` đọc. None = không phải event ta theo dõi / log pending.
+/// A DEX or token log ⇒ JSON with the keys `dex_fill_ingest` reads. None = not ours, or a pending log.
 pub fn encode_event(log: &Log) -> Option<Value> {
     let mut v = json!({
         "contract": format!("{:#x}", log.address()),
@@ -800,43 +909,34 @@ pub fn encode_event(log: &Log) -> Option<Value> {
     });
     let topic0 = *log.topic0()?;
     let a = |x: Address| format!("{x:#x}");
-    if topic0 == ISCaaSDex::OrderFilled::SIGNATURE_HASH {
-        let e = log.log_decode::<ISCaaSDex::OrderFilled>().ok()?.inner.data;
-        let f = e.fill;
-        v["event"] = json!("OrderFilled");
-        v["tag"] = json!(format!("{:#x}", e.tag));
+    if topic0 == ISCaaSDex::LegSettled::SIGNATURE_HASH {
+        let e = log.log_decode::<ISCaaSDex::LegSettled>().ok()?.inner.data;
+        v["event"] = json!("LegSettled");
+        v["tag"] = json!(format!("{:#x}", e.r#ref));
         v["order_hash"] = json!(format!("{:#x}", e.orderHash));
-        v["owner"] = json!(a(e.owner));
-        v["sell_token"] = json!(a(f.sellToken));
-        v["sold"] = json!(f.sold.to_string());
-        v["buy_token"] = json!(a(f.buyToken));
-        v["received"] = json!(f.received.to_string());
-        v["dex_fee"] = json!(f.dexFee.to_string());
-        v["dex_fee_recipient"] = json!(a(f.dexFeeRecipient));
-        v["relayer_fee_token"] = json!(a(f.relayerFeeToken));
-        v["relayer_fee"] = json!(f.relayerFee.to_string());
-        v["relayer_fee_recipient"] = json!(a(f.relayerFeeRecipient));
-        v["filled_total"] = json!(f.filledTotal.to_string());
-    } else if topic0 == ISCaaSDex::Matched::SIGNATURE_HASH {
-        let e = log.log_decode::<ISCaaSDex::Matched>().ok()?.inner.data;
-        v["event"] = json!("Matched");
-        v["tag"] = json!(format!("{:#x}", e.tag));
-        v["maker_hash"] = json!(format!("{:#x}", e.makerHash));
-        v["taker_hash"] = json!(format!("{:#x}", e.takerHash));
+        v["from"] = json!(a(e.from));
+        v["destination"] = json!(a(e.destination));
+        v["sold"] = json!(e.sold.to_string());
+        v["received"] = json!(e.received.to_string());
+        v["dex_fee"] = json!(e.dexFee.to_string());
+        v["refund"] = json!(e.refund.to_string());
+        v["relayer_share"] = json!(e.relayerShare.to_string());
+        v["treasury_share"] = json!(e.treasuryShare.to_string());
     } else if topic0 == ISCaaSDex::MatchFailed::SIGNATURE_HASH {
         let e = log.log_decode::<ISCaaSDex::MatchFailed>().ok()?.inner.data;
         v["event"] = json!("MatchFailed");
-        v["tag"] = json!(format!("{:#x}", e.tag));
+        v["tag"] = json!(format!("{:#x}", e.r#ref));
         v["reason"] = json!(revert_name(&e.reason));
     } else if topic0 == ISCaaSDex::OrderCancelled::SIGNATURE_HASH {
         let e = log.log_decode::<ISCaaSDex::OrderCancelled>().ok()?.inner.data;
         v["event"] = json!("OrderCancelled");
         v["order_hash"] = json!(format!("{:#x}", e.orderHash));
-        v["maker"] = json!(a(e.maker));
+        v["from"] = json!(a(e.from));
     } else if topic0 == ISCaaSDex::NoncesInvalidated::SIGNATURE_HASH {
         let e = log.log_decode::<ISCaaSDex::NoncesInvalidated>().ok()?.inner.data;
         v["event"] = json!("NoncesInvalidated");
-        v["maker"] = json!(a(e.maker));
+        v["from"] = json!(a(e.from));
+        v["batch"] = json!(e.batch.to_string());
         v["min_nonce"] = json!(e.minNonce.to_string());
     } else {
         return None;
@@ -848,42 +948,7 @@ pub fn encode_event(log: &Log) -> Option<Value> {
 mod tests {
     use super::*;
     use alloy::primitives::LogData;
-
-    #[test]
-    fn funded_counts_the_relayer_fee_in_either_token() {
-        let c = |status, fundable: u64, fee: u64| ISCaaSDex::checkOrderReturn {
-            h: B256::ZERO,
-            status,
-            remaining: U256::from(100),
-            fundable: U256::from(fundable),
-            feeFundable: U256::from(fee),
-        };
-        let mut o = Order {
-            maker: Address::ZERO,
-            taker: Address::ZERO,
-            sellToken: Address::repeat_byte(1),
-            buyToken: Address::repeat_byte(3),
-            sellAmount: U256::from(100),
-            buyAmount: U256::from(100),
-            nonce: U256::ZERO,
-            expiry: U256::ZERO,
-            maxFeePpm: 0,
-            flags: 0,
-            relayer: Address::ZERO,
-            feeMode: 0,
-            fee: U256::ZERO,
-            feeToken: Address::ZERO,
-            feeRecipient: Address::ZERO,
-        };
-        o.feeMode = 2; // FIXED 5, paid in the sell token
-        o.fee = U256::from(5);
-        assert!(funded(&o, U256::from(100), &c(ST_OK, 105, 0)));
-        assert!(!funded(&o, U256::from(100), &c(ST_OK, 104, 0)), "1 wei short of the fee");
-        assert!(!funded(&o, U256::from(100), &c(ST_OK + 1, 1_000, 0)));
-        o.feeToken = Address::repeat_byte(2); // separate fee token
-        assert!(funded(&o, U256::from(100), &c(ST_OK, 100, 5)));
-        assert!(!funded(&o, U256::from(100), &c(ST_OK, 100, 4)));
-    }
+    use alloy::sol_types::SolError;
 
     fn log_of(data: LogData) -> Log {
         Log {
@@ -897,46 +962,43 @@ mod tests {
     }
 
     #[test]
-    fn order_filled_is_encoded_for_odoo() {
-        let ev = ISCaaSDex::OrderFilled {
-            tag: B256::repeat_byte(1),
+    fn leg_settled_is_encoded_for_the_client() {
+        let ev = ISCaaSDex::LegSettled {
+            r#ref: B256::repeat_byte(1),
             orderHash: B256::repeat_byte(2),
-            owner: Address::repeat_byte(3),
-            fill: super::super::Fill {
-                sellToken: Address::repeat_byte(4),
-                sold: U256::from(100),
-                buyToken: Address::repeat_byte(5),
-                received: U256::from(199),
-                dexFee: U256::from(1),
-                dexFeeRecipient: Address::repeat_byte(6),
-                relayerFeeToken: Address::ZERO,
-                relayerFee: U256::ZERO,
-                relayerFeeRecipient: Address::ZERO,
-                filledTotal: U256::from(100),
-            },
+            from: Address::repeat_byte(3),
+            destination: Address::repeat_byte(4),
+            sold: U256::from(100),
+            received: U256::from(199),
+            dexFee: U256::from(1),
+            refund: U256::ZERO,
+            relayerShare: U256::ZERO,
+            treasuryShare: U256::from(1),
         };
         let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
-        assert_eq!(v["event"], "OrderFilled");
-        assert_eq!(v["received"], "199");
-        assert_eq!(v["dex_fee"], "1");
-        assert_eq!(v["owner"], format!("{:#x}", Address::repeat_byte(3)));
+        assert_eq!((v["event"].as_str(), v["received"].as_str(), v["dex_fee"].as_str()), (Some("LegSettled"), Some("199"), Some("1")));
+        assert_eq!(v["tag"], format!("{:#x}", B256::repeat_byte(1)));
+        assert_eq!(v["from"], format!("{:#x}", Address::repeat_byte(3)));
     }
 
     #[test]
-    fn cancel_and_invalidate_are_encoded() {
-        let ev = ISCaaSDex::OrderCancelled { orderHash: B256::repeat_byte(7), maker: Address::repeat_byte(8) };
+    fn cancels_invalidations_and_failures_are_encoded() {
+        let ev = ISCaaSDex::OrderCancelled { orderHash: B256::repeat_byte(7), from: Address::repeat_byte(8) };
+        assert_eq!(encode_event(&log_of(ev.encode_log_data())).unwrap()["event"], "OrderCancelled");
+        let ev = ISCaaSDex::NoncesInvalidated { from: Address::repeat_byte(8), batch: U256::from(2), minNonce: U256::from(9) };
         let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
-        assert_eq!(v["event"], "OrderCancelled");
-        let ev = ISCaaSDex::NoncesInvalidated { maker: Address::repeat_byte(8), minNonce: U256::from(9) };
-        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
-        assert_eq!(v["min_nonce"], "9");
-        let ev = ISCaaSDex::MatchFailed { tag: B256::ZERO, reason: Bytes::from_static(&[1, 2, 3]) };
-        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
-        assert!(v["reason"].as_str().unwrap().starts_with("revert 0x"));
+        assert_eq!((v["batch"].as_str(), v["min_nonce"].as_str()), (Some("2"), Some("9")));
+        let ev = ISCaaSDex::MatchFailed { r#ref: B256::ZERO, reason: Bytes::from_static(&[1, 2, 3]) };
+        assert!(encode_event(&log_of(ev.encode_log_data())).unwrap()["reason"].as_str().unwrap().starts_with("revert 0x"));
+        // P2b-2: an empty reason is out of gas inside the settlement, never an order's fault
+        let ev = ISCaaSDex::MatchFailed { r#ref: B256::ZERO, reason: Bytes::new() };
+        assert_eq!(encode_event(&log_of(ev.encode_log_data())).unwrap()["reason"], "out_of_gas");
+        let reason = IToken::BelowMinFill { orderHash: B256::repeat_byte(5) }.abi_encode();
+        assert!(revert_name(&reason).starts_with("BelowMinFill"));
     }
 
     #[test]
-    fn cancel_rate_limit_is_per_maker_and_per_hour() {
+    fn cancel_rate_limit_is_per_signer_and_per_hour() {
         let mut q = CancelQueue::default();
         let m = Address::repeat_byte(1);
         for _ in 0..ONCHAIN_CANCELS_PER_HOUR {
@@ -950,66 +1012,60 @@ mod tests {
     const BASE: Address = Address::repeat_byte(0xaa);
     const QUOTE: Address = Address::repeat_byte(0xbb);
 
-    fn rest(maker: u8, sell: Address, buy: Address) -> Resting {
-        let order = Order {
-            maker: Address::repeat_byte(maker),
-            taker: Address::ZERO,
-            sellToken: sell,
-            buyToken: buy,
-            sellAmount: U256::from(1000),
-            buyAmount: U256::from(1000),
-            nonce: U256::ZERO,
-            expiry: U256::from(maker),
-            maxFeePpm: 0,
-            flags: 0,
-            relayer: Address::ZERO,
-            feeMode: 0,
+    fn rest(from: u8, sell: Address, receive: Address) -> Resting {
+        let order = TradeOrder {
+            from: Address::repeat_byte(from),
+            receiveToken: receive,
+            amount: U256::from(1000),
+            receiveAmount: U256::from(1000),
+            minFill: U256::ZERO,
             fee: U256::ZERO,
-            feeToken: Address::ZERO,
-            feeRecipient: Address::ZERO,
+            relayer: Address::ZERO,
+            dex: Address::ZERO,
+            destination: Address::ZERO,
+            flags: 0,
+            batch: U256::ZERO,
+            nonce: U256::ZERO,
+            validUntil: U256::from(from),
         };
-        Resting { hash: B256::repeat_byte(maker), order, sig: Bytes::new(), remaining: U256::from(1000), seq: 0 }
+        Resting { hash: B256::repeat_byte(from), sell, order, sig: Bytes::new(), remaining: U256::from(1000), seq: 0 }
     }
 
-    fn fill(market_id: i64, tag: u8, maker: Resting, taker: Resting, maker_fill: u64, taker_fill: u64) -> PlannedFill {
-        PlannedFill {
-            tag: B256::repeat_byte(tag),
-            market_id,
-            maker,
-            taker,
-            maker_fill: U256::from(maker_fill),
-            taker_fill: U256::from(taker_fill),
-        }
+    fn settlement(market_id: i64, tag: u8, maker: Resting, taker: Resting, x: u64, y: u64) -> PlannedSettlement {
+        PlannedSettlement { tag: B256::repeat_byte(tag), market_id, taker, taker_fill: U256::from(y),
+                            makers: vec![(maker, U256::from(x), U256::from(y))] }
     }
 
     #[test]
     fn trade_tape_reads_side_and_price_from_the_market_base() {
-        // taker buys base: maker sells 10 base for 20 quote ⇒ price 20/10, base 10, "buy"
-        let buy = fill(1, 1, rest(1, BASE, QUOTE), rest(2, QUOTE, BASE), 10, 20);
+        // the taker buys base: the maker sells 10 base for 20 quote ⇒ 20/10, base 10, "buy"
+        let buy = settlement(1, 1, rest(1, BASE, QUOTE), rest(2, QUOTE, BASE), 10, 20);
         let t = trade_view(&buy, BASE, 7);
         assert_eq!((t.price.as_str(), t.base_amount.as_str(), t.taker_side), ("20/10", "10", "buy"));
-        // taker sells base: maker (bid) sells 20 quote, taker gives 10 base ⇒ same price, "sell"
-        let sell = fill(1, 2, rest(1, QUOTE, BASE), rest(2, BASE, QUOTE), 20, 10);
+        // the taker sells base: the maker (a bid) sells 20 quote, the taker gives 10 base ⇒ same price, "sell"
+        let sell = settlement(1, 2, rest(1, QUOTE, BASE), rest(2, BASE, QUOTE), 20, 10);
         let t = trade_view(&sell, BASE, 7);
         assert_eq!((t.price.as_str(), t.base_amount.as_str(), t.taker_side), ("20/10", "10", "sell"));
     }
 
     #[test]
-    fn settle_and_cancel_jobs_are_one_per_market() {
+    fn settle_jobs_are_one_per_market_and_cancels_go_where_the_order_lives() {
         let dex = Address::repeat_byte(0xd);
-        let fills = [
-            fill(1, 1, rest(1, BASE, QUOTE), rest(2, QUOTE, BASE), 10, 20),
-            fill(2, 2, rest(3, BASE, QUOTE), rest(4, QUOTE, BASE), 10, 20),
-            fill(1, 3, rest(5, BASE, QUOTE), rest(6, QUOTE, BASE), 10, 20),
+        let ss = [
+            settlement(1, 1, rest(1, BASE, QUOTE), rest(2, QUOTE, BASE), 10, 20),
+            settlement(2, 2, rest(3, BASE, QUOTE), rest(4, QUOTE, BASE), 10, 20),
+            settlement(1, 3, rest(5, BASE, QUOTE), rest(6, QUOTE, BASE), 10, 20),
         ];
-        let jobs = settle_jobs(dex, &fills);
+        let jobs = settle_jobs(dex, &ss);
         let seen: Vec<(i64, usize)> =
             jobs.iter().map(|j| (j["market_id"].as_i64().unwrap(), j["tags"].as_array().unwrap().len())).collect();
         assert_eq!(seen, vec![(1, 2), (2, 1)]);
-        let req = |m: u8| CancelReq { order: rest(m, BASE, QUOTE).order, sig: Bytes::new() };
-        let pending = vec![(1, req(1)), (2, req(2)), (1, req(3))];
-        let jobs = cancel_jobs(dex, &pending);
-        let seen: Vec<i64> = jobs.iter().map(|j| j["market_id"].as_i64().unwrap()).collect();
-        assert_eq!(seen, vec![1, 2]);
+        assert_eq!(jobs[0]["valid_until"], "1", "the earliest leg's deadline");
+        let c = |m: i64, from: u8, kind: u8| (m, BASE, kind, rest(from, BASE, QUOTE).order, Bytes::from_static(&[1]));
+        let jobs = cancel_jobs(dex, &[c(1, 1, KIND_SCAAS), c(2, 2, KIND_OUTSIDE), c(1, 3, KIND_OUTSIDE)]);
+        let kinds: Vec<(&str, i64)> = jobs.iter().map(|j| (j["kind"].as_str().unwrap(), j["market_id"].as_i64().unwrap())).collect();
+        assert_eq!(kinds, vec![("metatx", 1), ("cancel", 1), ("cancel", 2)]);
+        assert_eq!((jobs[0]["entry"].as_str(), jobs[0]["token"].as_str()), (Some("mtxCancelOrder"), Some(&*format!("{BASE:#x}"))));
+        assert_eq!(jobs[1]["target"], format!("{dex:#x}"));
     }
 }
diff --git a/scaas-node/src/gateway.rs b/scaas-node/src/gateway.rs
index 9322441..99ac88f 100644
--- a/scaas-node/src/gateway.rs
+++ b/scaas-node/src/gateway.rs
@@ -49,9 +49,13 @@ pub struct SignedReq {
     pub signature: String,
 }
 
+/// `POST /v1/dex/orders`: the `TradeOrder` and its sell token (the token's domain signs a SCaaS order, the DEX's an
+/// outside one, NODE-DEX-15).
 #[derive(Deserialize)]
 pub struct OrderReq {
     pub chain: u64,
+    #[serde(rename = "sellToken")]
+    pub sell_token: Address,
     pub order: WireOrder,
     pub signature: String,
 }
@@ -64,10 +68,15 @@ pub struct CancelReqBody {
     pub signature: String,
 }
 
+/// `POST /v1/dex/cancel-all`: `InvalidateNonces(from, batch, minNonce)` in the sell token's domain (its SCaaS orders)
+/// or the DEX's (outside-token orders).
 #[derive(Deserialize)]
 pub struct CancelAllReq {
     pub chain: u64,
-    pub maker: Address,
+    #[serde(rename = "sellToken")]
+    pub sell_token: Address,
+    pub from: Address,
+    pub batch: String,
     #[serde(rename = "minNonce")]
     pub min_nonce: String,
     pub signature: String,
@@ -200,7 +209,7 @@ async fn dex_place(State(s): State<AppState>, Json(r): Json<OrderReq>) -> Reply
         Ok(v) => v,
         Err(e) => return e,
     };
-    match v.place(&r.order, &r.signature).await {
+    match v.place(r.sell_token, &r.order, &r.signature).await {
         Ok(p) => (StatusCode::ACCEPTED, Json(serde_json::to_value(p).unwrap_or_default())),
         Err(e) => venue_err(e),
     }
@@ -222,8 +231,10 @@ async fn dex_cancel_all(State(s): State<AppState>, Json(r): Json<CancelAllReq>)
         Ok(v) => v,
         Err(e) => return e,
     };
-    let Ok(min) = r.min_nonce.parse::<U256>() else { return bad("minNonce is not a uint256") };
-    match v.cancel_all(r.maker, min, &r.signature).await {
+    let (Ok(batch), Ok(min)) = (crate::metatx::uint(&r.batch), crate::metatx::uint(&r.min_nonce)) else {
+        return bad("batch and minNonce are decimal uint256");
+    };
+    match v.cancel_all(r.sell_token, r.from, batch, min, &r.signature).await {
         Ok(n) => (StatusCode::ACCEPTED, Json(json!({"status": "cancelled", "orders": n}))),
         Err(e) => venue_err(e),
     }
diff --git a/scaas-node/src/odoo.rs b/scaas-node/src/odoo.rs
index 2941997..cc08ce3 100644
--- a/scaas-node/src/odoo.rs
+++ b/scaas-node/src/odoo.rs
@@ -90,6 +90,23 @@ pub struct Job {
     pub metatx: Option<Value>,
     #[serde(default)]
     pub call: Option<WireCall>,
+    /// A token's other signed entry point (job-api.md, order and wrap entries): `mtxCancelOrder` (`order`),
+    /// `mtxInvalidateNonces` (`from`, `batch`, `newMin`), `mtxWrap` (`underlying`, `order`); `token` is the target.
+    #[serde(default)]
+    pub entry: Option<String>,
+    #[serde(default)]
+    pub order: Option<Value>,
+    #[serde(default)]
+    pub from: Option<String>,
+    #[serde(default)]
+    pub batch: Option<String>,
+    #[serde(default, rename = "newMin")]
+    pub new_min: Option<String>,
+    #[serde(default)]
+    pub underlying: Option<Address>,
+    /// Deadline of an entry job that carries none of its own (cancels never expire on chain).
+    #[serde(default, rename = "validUntil")]
+    pub valid_until: Option<String>,
     /// `metatx` | `call` | `signed_op` (họ không phải EVM: payload ký + chữ ký + khoá công khai, adapter tự đọc).
     #[serde(default)]
     pub kind: Option<String>,
diff --git a/scaas-node/src/submit.rs b/scaas-node/src/submit.rs
index ddaba11..2abb758 100644
--- a/scaas-node/src/submit.rs
+++ b/scaas-node/src/submit.rs
@@ -17,8 +17,9 @@ use tracing::{info, warn};
 
 use crate::breaker::Breaker;
 use crate::chain::{Chain, SimError};
+use crate::abi::IToken;
 use crate::config::ChainCfg;
-use crate::metatx::Mtx;
+use crate::metatx::{addr, uint, Mtx};
 use crate::nonce::{bump, plan, Inflight};
 use crate::odoo::{Job, Odoo, Report};
 
@@ -105,6 +106,9 @@ struct Sent {
 }
 
 pub fn work_from_job(job: &Job) -> Result<Work> {
+    if let Some(e) = job.entry.as_deref() {
+        return entry_work(job, e);
+    }
     if let Some(c) = &job.call {
         let data = alloy::hex::decode(c.calldata.strip_prefix("0x").unwrap_or(&c.calldata))?;
         let valid_until = c.valid_until.parse::<u64>()?;
@@ -120,6 +124,40 @@ pub fn work_from_job(job: &Job) -> Result<Work> {
     Ok(Work { job_id: Some(job.id), to: token, data: m.calldata(sig.into()), valid_until, meta })
 }
 
+/// A token's other signed entry point as a `metatx` job (job-api.md, order and wrap entries): the signature is in the
+/// calldata, the target is `token`, no meta-tx lane is involved (`meta` None).
+fn entry_work(job: &Job, entry: &str) -> Result<Work> {
+    use alloy::sol_types::SolCall;
+    let (Some(token), Some(sig)) = (job.token, &job.signature) else {
+        anyhow::bail!("entry job {} without token or signature", job.id);
+    };
+    let sig: Bytes = alloy::hex::decode(sig.strip_prefix("0x").unwrap_or(sig))?.into();
+    let order = || -> Result<crate::abi::TradeOrder> {
+        let w = job.order.clone().ok_or_else(|| anyhow::anyhow!("entry {entry} without order"))?;
+        serde_json::from_value::<crate::dex::WireOrder>(w)?.to_sol()
+    };
+    let deadline = || -> Result<u64> {
+        Ok(job.valid_until.as_deref().ok_or_else(|| anyhow::anyhow!("entry {entry} without validUntil"))?.parse()?)
+    };
+    let text = |v: &Option<String>, f: &str| v.clone().ok_or_else(|| anyhow::anyhow!("entry {entry} without {f}"));
+    let (data, valid_until) = match entry {
+        "mtxCancelOrder" => (IToken::mtxCancelOrderCall { o: order()?, sig }.abi_encode(), deadline()?),
+        "mtxInvalidateNonces" => {
+            let (from, batch, new_min) = (addr(&text(&job.from, "from")?)?, uint(&text(&job.batch, "batch")?)?,
+                uint(&text(&job.new_min, "newMin")?)?);
+            (IToken::mtxInvalidateNoncesCall { from, batch, newMin: new_min, sig }.abi_encode(), deadline()?)
+        }
+        "mtxWrap" => {
+            let o = order()?;
+            let until = o.validUntil.saturating_to();
+            let underlying = job.underlying.ok_or_else(|| anyhow::anyhow!("mtxWrap without underlying"))?;
+            (IToken::mtxWrapCall { underlying, o, sig }.abi_encode(), until)
+        }
+        e => anyhow::bail!("unknown entry {e:?}"),
+    };
+    Ok(Work { job_id: Some(job.id), to: token, data: data.into(), valid_until, meta: None })
+}
+
 pub fn now() -> u64 {
     std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
 }
@@ -813,6 +851,35 @@ mod tests {
         }
     }
 
+    /// The token's order entries as `metatx` jobs (job-api.md): byte-identical with the forge KAT's relayed calldata.
+    #[test]
+    fn entry_jobs_encode_as_the_token_reads_them() {
+        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/trade_kat.json");
+        let k: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
+        let s = |f: &str| k[f].as_str().unwrap().to_string();
+        let o = <crate::abi::TradeOrder as SolValue>::abi_decode(&alloy::hex::decode(&s("order_abi")[2..]).unwrap()).unwrap();
+        let token = s("verifying_contract");
+        let job = |v: Value| -> crate::odoo::Job { serde_json::from_value(v).unwrap() };
+        let cancel = job(json!({"id": 1, "kind": "metatx", "entry": "mtxCancelOrder", "token": token,
+            "order": crate::dex::WireOrder::from_sol(&o), "signature": s("cancel_signature"), "validUntil": "1800000300"}));
+        let w = work_from_job(&cancel).unwrap();
+        assert_eq!((format!("0x{}", alloy::hex::encode(&w.data)), w.valid_until, w.meta), (s("cancel_calldata").to_lowercase(), 1_800_000_300, None));
+        let inv = job(json!({"id": 2, "kind": "metatx", "entry": "mtxInvalidateNonces", "token": token,
+            "from": s("signer").to_lowercase(), "batch": s("invalidate_batch"), "newMin": s("invalidate_min_nonce"),
+            "signature": s("invalidate_signature"), "validUntil": "1800000300"}));
+        assert_eq!(format!("0x{}", alloy::hex::encode(&work_from_job(&inv).unwrap().data)), s("invalidate_calldata").to_lowercase());
+        let wrap = job(json!({"id": 3, "kind": "metatx", "entry": "mtxWrap", "token": token, "underlying": format!("{:#x}", TOKEN),
+            "order": crate::dex::WireOrder::from_sol(&o), "signature": s("order_signature")}));
+        let w = work_from_job(&wrap).unwrap();
+        assert_eq!((&w.data[..4], w.valid_until), (&[0x3e, 0xd1, 0x8b, 0xa8][..], o.validUntil.saturating_to()));
+        for bad in [json!({"id": 4, "kind": "metatx", "entry": "mtxTrade", "token": token, "signature": "0x00"}),
+                    json!({"id": 5, "kind": "metatx", "entry": "mtxCancelOrder", "token": token, "signature": "0x00", "validUntil": "1"}),
+                    json!({"id": 6, "kind": "metatx", "entry": "mtxCancelOrder", "token": token, "signature": "0x00",
+                           "order": crate::dex::WireOrder::from_sol(&o)})] {
+            assert!(work_from_job(&job(bad)).is_err(), "mtxTrade is never a job; an order and a deadline are needed");
+        }
+    }
+
     /// Review H6/N2: cùng digest từ gateway (lane A) và outbox (lane B) ⇒ một chữ ký; job outbox bỏ qua trước claim.
     /// Lỗi tạm thời nhả digest ngay (không ai bị chặn tới hết hạn).
     #[tokio::test]
diff --git a/scaas-node/tests/e2e.rs b/scaas-node/tests/e2e.rs
index ed9681d..8d5f717 100644
--- a/scaas-node/tests/e2e.rs
+++ b/scaas-node/tests/e2e.rs
@@ -3,9 +3,10 @@
 //! Cần `anvil` và `forge` trong PATH. Chứng minh trên EVM thật với contract thật:
 //! 1. job outbox (giả Odoo) → simulate → ký → `signed` trước khi gửi → broadcast → receipt →
 //!    indexer gửi `PaymentSettled` + `MetaTransactionExecuted` vùng final;
-//! 2. DEX (R35): approve meta-tx qua gateway → lệnh ký EIP-712 qua gateway → khớp một phần →
-//!    job `settle` qua outbox (giả Odoo) → số dư + phí; khởi động lại venue ⇒ sổ còn nguyên; huỷ ⇒
-//!    đóng on-chain; watcher đưa event final về Odoo. Người ký không có một wei gas nào.
+//! 2. DEX (R35, NODE-DEX-15) on a `SCaaSDex` clone: `TradeOrder`s signed in the sell token's domain (a `DexOrder` in
+//!    the DEX's domain for an outside token) through the gateway → one settlement per taker → `mtxSettle` job through
+//!    the outbox (fake Odoo) → balances, fees, relayer share; restart ⇒ same book; cancels on the token (entry job)
+//!    and on the DEX; the watcher brings final events back. No signer holds a wei of gas.
 use std::net::SocketAddr;
 use std::process::{Child, Command, Stdio};
 use std::collections::BTreeMap;
@@ -27,7 +28,8 @@ use scaas_node::abi::{IToken, MetaTransfer};
 use scaas_node::chain::Chain;
 use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
 use scaas_node::dex::venue::Venue;
-use scaas_node::dex::{cancel_digest, domain, order_hash, Order, WireOrder};
+use scaas_node::abi::TradeOrder;
+use scaas_node::dex::{cancel_digest, dex_order_hash, domain, invalidate_digest, trade_order_hash, WireOrder};
 use scaas_node::gateway::{router, AppState, GwChain};
 use scaas_node::metatx::{Domain, Mtx, MODE_RESTRICT_RELAYER};
 use scaas_node::odoo::Odoo;
@@ -181,8 +183,7 @@ async fn fake(
                 .orders
                 .values()
                 .filter(|r| r["state"] == "open" || r["state"] == "partial")
-                .map(|r| json!({"order_hash": r["order_hash"], "order": r["order"], "signature": r["signature"],
-                                 "remaining": r["remaining"], "seq": r["seq"]}))
+                .map(row_of)
                 .collect();
             json!({"rows": rows})
         }
@@ -199,8 +200,15 @@ async fn fake(
             for j in body["jobs"].as_array().unwrap() {
                 o.next_job += 1;
                 let id = 1000 + o.next_job;
-                o.jobs.push(json!({"id": id, "kind": "call", "call": {
-                    "target": j["target"], "calldata": j["calldata"], "validUntil": j["valid_until"]}}));
+                // a token-side order entry is a `metatx` job naming its entry; everything else a `call` on the DEX
+                o.jobs.push(if j["kind"] == "metatx" {
+                    let mut x = j.clone();
+                    x["id"] = json!(id);
+                    x
+                } else {
+                    json!({"id": id, "kind": "call", "call": {
+                        "target": j["target"], "calldata": j["calldata"], "validUntil": j["valid_until"]}})
+                });
             }
             json!({"ok": true})
         }
@@ -216,6 +224,12 @@ async fn fake(
     (StatusCode::OK, Json(out))
 }
 
+/// A stored order as `dex_book_load` / `dex_sync` return it.
+fn row_of(r: &Value) -> Value {
+    json!({"order_hash": r["order_hash"], "sell_token": r["sell_token"], "order": r["order"], "signature": r["signature"],
+           "remaining": r["remaining"], "seq": r["seq"]})
+}
+
 async fn start_fake(state: Arc<Mutex<FakeOdoo>>) -> SocketAddr {
     let app = Router::new().route("/json/2/{model}/{method}", post(fake)).with_state(state);
     let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
@@ -375,26 +389,25 @@ fn sign_hash(signer: &PrivateKeySigner, h: B256) -> String {
     format!("0x{}", alloy::hex::encode(signer.sign_hash_sync(&h).unwrap().as_bytes()))
 }
 
+/// A `TradeOrder` on the venue's DEX: sells `amount` for at least `receive_amount` of `receive`, home-bound to the lane.
 #[allow(clippy::too_many_arguments)]
-fn order(maker: &PrivateKeySigner, sell: Address, sell_amt: u64, buy: Address, buy_amt: u64, nonce: u64, relayer: Address)
-    -> Order
+fn order(from: &PrivateKeySigner, receive: Address, amount: u64, receive_amount: u64, fee: u64, nonce: u64, relayer: Address,
+    dex: Address) -> TradeOrder
 {
-    Order {
-        maker: maker.address(),
-        taker: Address::ZERO,
-        sellToken: sell,
-        buyToken: buy,
-        sellAmount: U256::from(sell_amt),
-        buyAmount: U256::from(buy_amt),
-        nonce: U256::from(nonce),
-        expiry: U256::from(now() + 600),
-        maxFeePpm: 5_000,
-        flags: 0,
+    TradeOrder {
+        from: from.address(),
+        receiveToken: receive,
+        amount: U256::from(amount),
+        receiveAmount: U256::from(receive_amount),
+        minFill: U256::ZERO,
+        fee: U256::from(fee),
         relayer,
-        feeMode: 0,
-        fee: U256::ZERO,
-        feeToken: Address::ZERO,
-        feeRecipient: Address::ZERO,
+        dex,
+        destination: Address::ZERO,
+        flags: 0,
+        batch: U256::from(1),
+        nonce: U256::from(nonce),
+        validUntil: U256::from(now() + 600),
     }
 }
 
@@ -420,10 +433,32 @@ async fn drain(s: &mut Submitter, rx: &mut mpsc::Receiver<Work>) {
 }
 
 alloy::sol! {
-    function setMarket(address tokenA, address tokenB, (bool,bool,uint32,uint32,address) m) external;
-    function filled(bytes32 h) external view returns (uint256);
-    function createMetaToken(uint64 version, address underlying, bytes initData, bytes32 salt) external returns (address token);
+    struct DexConfig { address admin; uint32 relayerSharePpm; address treasury; bool listedOnly; }
+    function createDex(uint64 version, DexConfig cfg, bytes32 salt) external returns (address dex);
+    function setMarket(address base, address quote, bool listed) external;
     function approve(address spender, uint256 value) external returns (bool);
+    function mint(address to, uint256 value) external;
+    function puller() external view returns (address);
+}
+
+/// `eth_call` then send: the return value of a state-changing call (the DEX address from `createDex`).
+async fn create(rpc: &str, from: &PrivateKeySigner, to: Address, data: Vec<u8>) -> Address {
+    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
+    let out = p.call(TransactionRequest::default().from(from.address()).to(to).input(data.clone().into())).await.unwrap();
+    send(rpc, from, to, data).await;
+    Address::abi_decode(&out).unwrap()
+}
+
+/// A plain ERC-20 the factory never made (an "outside" token): `MockERC20` from the forge build the deploy just ran.
+async fn deploy_outside_token(rpc: &str, from: &PrivateKeySigner) -> Address {
+    let sc = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm");
+    let raw = std::fs::read_to_string(format!("{sc}/out/Mocks.sol/MockERC20.json")).expect("forge build output of test/helpers/Mocks.sol");
+    let v: Value = serde_json::from_str(&raw).unwrap();
+    let mut code = alloy::hex::decode(v["bytecode"]["object"].as_str().unwrap()).unwrap();
+    code.extend(("USD Coin".to_string(), "USDC".to_string(), U256::from(6u8)).abi_encode_params());
+    let p = ProviderBuilder::new().wallet(EthereumWallet::from(from.clone())).connect_http(rpc.parse().unwrap());
+    let tx = alloy::network::TransactionBuilder::with_deploy_code(TransactionRequest::default(), code);
+    p.send_transaction(tx).await.unwrap().get_receipt().await.unwrap().contract_address.unwrap()
 }
 
 #[tokio::test]
@@ -434,39 +469,39 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
     let (_anvil, rpc) = start_anvil(chain_id, 18650).await;
     let alice = small_key(0xA11CE);
     let bob = small_key(0xB0B);
+    let dave = small_key(0xDA7E);
     let dep = deploy(&rpc, chain_id, alice.address());
-    let demo: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
-    let factory: Address = dep["factory"].as_str().unwrap().parse().unwrap();
-    let dex: Address = dep["scaas_dex"].as_str().unwrap().parse().unwrap();
-
-    // Base A (half to alice) and quote B (half to bob): v1 MetaTokens, because the built venue settles `SCaaSDexV1`
-    // over allowances until it moves to `SCaaSDex` (Task 4). Plain txs from the funded deployer (= DEX admin).
+    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
+    let token_a: Address = dep["demo_token"].as_str().unwrap().parse().unwrap(); // half to alice
+    // the quote token is the deploy's second demo token (half to alice as well): no `TokenConfig` encoded here
+    let token_b: Address = dep["demo_token_2"].as_str().unwrap().parse().unwrap();
+    let factory: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();
+
+    // 500 B to bob, a DEX clone with a 50 % relayer share, both markets listed — plain txs from the funded deployer
+    // (= DEX admin).
     let deployer = key(DEPLOYER);
-    let p = ProviderBuilder::new().wallet(EthereumWallet::from(deployer.clone())).connect_http(rpc.parse().unwrap());
-    let mut v1 = vec![];
-    for (name, supply, salt, holder) in [("AAA", 1_000_000_000_000u64, 0xaa, &alice), ("BBB", 1_000_000_000, 0xbb, &bob)] {
-        let init = (format!("Token {name}"), name.to_string(), U256::from(6u8), U256::from(supply), Address::ZERO).abi_encode_params();
-        let create = createMetaTokenCall { version: 1, underlying: Address::ZERO, initData: init.into(), salt: B256::repeat_byte(salt) };
-        let out = p.call(TransactionRequest::default().to(factory).input(create.abi_encode().into())).await.unwrap();
-        let t = Address::abi_decode(&out).unwrap();
-        send(&rpc, &deployer, factory, create.abi_encode()).await;
-        send(&rpc, &deployer, t, IToken::transferCall { to: holder.address(), value: U256::from(supply / 2) }.abi_encode()).await;
-        let _: Value = p.raw_request("anvil_setBalance".into(), (holder.address(), "0xde0b6b3a7640000")).await.unwrap();
-        send(&rpc, holder, t, approveCall { spender: dex, value: U256::MAX }.abi_encode()).await;
-        v1.push(t);
-    }
-    let (token_a, token_b) = (v1[0], v1[1]);
-    let fee_to = Address::repeat_byte(0xfe);
-    send(&rpc, &deployer, dex, setMarketCall { tokenA: token_a, tokenB: token_b, m: (true, true, 1_000, 2_000, fee_to) }.abi_encode()).await;
+    let alice_b0 = balance(&rpc, token_b, alice.address()).await;
+    send(&rpc, &deployer, token_b, IToken::transferCall { to: bob.address(), value: U256::from(500_000_000u64) }.abi_encode()).await;
+    let treasury = Address::repeat_byte(0x7a);
+    let dex = create(&rpc, &deployer, factory, createDexCall { version: 1, cfg: DexConfig { admin: deployer.address(),
+        relayerSharePpm: 500_000, treasury, listedOnly: false }, salt: B256::repeat_byte(0xde) }.abi_encode()).await;
+    send(&rpc, &deployer, dex, setMarketCall { base: token_a, quote: token_b, listed: true }.abi_encode()).await;
+    let usdc = deploy_outside_token(&rpc, &deployer).await;
+    send(&rpc, &deployer, usdc, mintCall { to: dave.address(), value: U256::from(1_000_000_000u64) }.abi_encode()).await;
+    send(&rpc, &deployer, dex, setMarketCall { base: token_a, quote: usdc, listed: true }.abi_encode()).await;
 
     let relayer = key(RELAYER);
+    let lane = relayer.address();
     let cfg = chain_cfg(chain_id, &rpc, Some(dex));
     let state = Arc::new(Mutex::new(FakeOdoo {
         tokens: vec![format!("{token_a:#x}"), format!("{token_b:#x}")],
         dex: format!("{dex:#x}"),
-        markets: vec![json!({"id": 1, "base": format!("{token_a:#x}"), "quote": format!("{token_b:#x}"),
-            "base_decimals": 6, "quote_decimals": 6, "fee_on": true, "maker_fee_ppm": 1000, "taker_fee_ppm": 2000,
-            "fee_recipient": format!("{fee_to:#x}"), "min_base_amount": "1000"})],
+        markets: vec![
+            json!({"id": 1, "base": format!("{token_a:#x}"), "quote": format!("{token_b:#x}"), "base_decimals": 6,
+                   "quote_decimals": 6, "maker_fee_ppm": 1000, "taker_fee_ppm": 2000, "min_base_amount": "1000"}),
+            json!({"id": 2, "base": format!("{token_a:#x}"), "quote": format!("{usdc:#x}"), "base_decimals": 6,
+                   "quote_decimals": 6, "maker_fee_ppm": 0, "taker_fee_ppm": 0, "min_base_amount": "0"}),
+        ],
         ..Default::default()
     }));
     let odoo = odoo_at(start_fake(state.clone()).await);
@@ -475,9 +510,10 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
         .unwrap();
     let shared = Arc::new(Chain::with_signer(&cfg, relayer.clone()).unwrap());
     let venue = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
+    assert_eq!(venue.markets().await.len(), 2, "both markets listed on the DEX, B SCaaS and USDC outside");
     let (tx, mut rx) = mpsc::channel::<Work>(16);
     let fee_wallet = Address::repeat_byte(0xfa);
-    let gw = GwChain { chain: shared.clone(), tx, tokens: Arc::new(RwLock::new(vec![token_a, token_b, demo])), dex: Some(venue.clone()), breaker: None, fee_recipient: Some(fee_wallet) };
+    let gw = GwChain { chain: shared.clone(), tx, tokens: Arc::new(RwLock::new(vec![token_a, token_b])), dex: Some(venue.clone()), breaker: None, fee_recipient: Some(fee_wallet) };
     let app = router(AppState { chains: Arc::new([(chain_id, gw)].into_iter().collect()) });
     let listener = tokio::net::TcpListener::bind("127.0.0.1:18651").await.unwrap();
     tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
@@ -498,98 +534,109 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
     let m = payment(alice.address(), Address::repeat_byte(0x5e), 1_000_000, B256::ZERO,
         U256::from_be_bytes(keccak256(b"e2e.r84").0), 0x20, thief, 1_000, thief); // FIXED fee, nothing bound
     let (kind, wire) = m.to_wire();
-    let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": demo, "struct": kind, "m": wire,
-        "signature": sign(&alice, &token_domain(&dep, chain_id, demo), &m)})).await;
+    let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": token_a, "struct": kind, "m": wire,
+        "signature": sign(&alice, &token_domain(&dep, chain_id, token_a), &m)})).await;
     assert_eq!(st, 202, "{body}");
     drain(&mut s, &mut rx).await;
-    assert_eq!((balance(&rpc, demo, fee_wallet).await, balance(&rpc, demo, thief).await), (U256::from(1_000u64), U256::ZERO));
+    assert_eq!((balance(&rpc, token_a, fee_wallet).await, balance(&rpc, token_a, thief).await), (U256::from(1_000u64), U256::ZERO));
 
-    let d = domain(chain_id, dex);
-    let place = |o: Order, signer: &PrivateKeySigner| {
-        let sig = sign_hash(signer, order_hash(&d, &o));
-        post("/v1/dex/orders", json!({"chain": chain_id, "order": WireOrder::from_sol(&o), "signature": sig}))
+    // SCaaS orders are signed in their sell token's salted domain: no allowance anywhere (CTR-TOK-01).
+    let hash = |sell: Address, o: &TradeOrder| trade_order_hash(&domain("SCaaS MetaToken", chain_id, sell, uid), o);
+    let place = |sell: Address, o: TradeOrder, signer: &PrivateKeySigner| {
+        let sig = sign_hash(signer, hash(sell, &o));
+        post("/v1/dex/orders", json!({"chain": chain_id, "sellToken": sell, "order": WireOrder::from_sol(&o), "signature": sig}))
     };
 
-    // 2. Order without the relayer restriction is refused (RS5-9).
-    let (st, _) = place(order(&alice, token_a, 100_000_000, token_b, 200_000_000, 1, Address::ZERO), &alice).await;
+    // 2. Not home-bound (RS5-9) or another DEX (NODE-DEX-16) ⇒ refused at the door.
+    let (st, _) = place(token_a, order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 1, Address::ZERO, dex), &alice).await;
+    assert_eq!(st, 400);
+    let (st, _) = place(token_a, order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 1, lane, token_b), &alice).await;
     assert_eq!(st, 400);
 
-    // 3. Ask rests; a smaller bid fills partially against it.
-    let ask = order(&alice, token_a, 100_000_000, token_b, 200_000_000, 2, relayer.address());
-    let ask_hash = order_hash(&d, &ask);
-    let (st, body) = place(ask.clone(), &alice).await;
+    // 3. The ask rests; a bid of more than half of it is the taker of one settlement (NODE-DEX-15).
+    let ask = order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 2, lane, dex);
+    let ask_hash = hash(token_a, &ask);
+    let (st, body) = place(token_a, ask.clone(), &alice).await;
     assert_eq!((st, body["status"].as_str()), (202, Some("resting")), "{body}");
-    let bid = order(&bob, token_b, 80_000_000, token_a, 40_000_000, 3, relayer.address());
-    let (st, body) = place(bid, &bob).await;
+    let small = order(&bob, token_a, 80_000_000, 40_000_000, 2_000, 3, lane, dex);
+    let (st, body) = place(token_b, small, &bob).await;
+    assert_eq!((st, body["status"].as_str()), (202, Some("cancelled")), "below the ask's minimum fill, it cannot rest crossed: {body}");
+    let bid = order(&bob, token_a, 120_000_000, 60_000_000, 2_000, 4, lane, dex);
+    let (st, body) = place(token_b, bid, &bob).await;
     assert_eq!((st, body["status"].as_str()), (202, Some("filled")), "{body}");
-    drain(&mut s, &mut rx).await; // the settle job went through the Odoo outbox
-    // maker fee 0.1 % of 80 B, taker fee 0.2 % of 40 A
-    assert_eq!(balance(&rpc, token_b, alice.address()).await, U256::from(80_000_000u64 - 80_000));
-    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(40_000_000u64 - 80_000));
-    assert_eq!(balance(&rpc, token_b, fee_to).await, U256::from(80_000u64));
-    assert_eq!(balance(&rpc, token_a, fee_to).await, U256::from(80_000u64));
+    drain(&mut s, &mut rx).await; // the mtxSettle job went through the client outbox
+    // the maker gets 120 B less its fee ceil(120e6 × 1000 / 1e6); the taker 60 A less ceil(60e6 × 2000 / 1e6);
+    // half of each fee to the lane that submitted, half to the treasury
+    assert_eq!(balance(&rpc, token_b, alice.address()).await, alice_b0 + U256::from(120_000_000u64 - 120_000));
+    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(60_000_000u64 - 120_000));
+    assert_eq!((balance(&rpc, token_b, lane).await, balance(&rpc, token_b, treasury).await), (U256::from(60_000u64), U256::from(60_000u64)));
+    assert_eq!((balance(&rpc, token_a, lane).await, balance(&rpc, token_a, treasury).await), (U256::from(60_000u64), U256::from(60_000u64)));
     assert_eq!(balance(&rpc, token_a, dex).await + balance(&rpc, token_b, dex).await, U256::ZERO);
 
-    // 4. Restart: a fresh venue on the same Odoo has the same book.
+    // 4. Restart: a fresh venue on the same client has the same book.
     let before = venue.rows().await;
     assert_eq!(before.len(), 1);
-    assert_eq!(before[0].remaining, "60000000");
+    assert_eq!(before[0].remaining, "40000000");
     let venue2 = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
     assert_eq!(venue2.rows().await, before);
 
-    // 5. A failed commit leaves the book exactly as Odoo has it (review D20).
+    // 5. A failed commit leaves the book exactly as the client has it (review D20).
     state.lock().unwrap().fail_commits = 1;
-    let (st, _) = place(order(&bob, token_b, 20_000_000, token_a, 10_000_000, 4, relayer.address()), &bob).await;
+    let (st, _) = place(token_b, order(&bob, token_a, 80_000_000, 40_000_000, 2_000, 5, lane, dex), &bob).await;
     assert_eq!(st, 503);
     assert_eq!(venue.rows().await, before);
 
-    // 6. Cancel: a high-s copy of a valid signature is refused like the contract would (review I4);
-    //    the canonical one takes the order off the book now and closes it on-chain at the next sync.
+    // 6. Cancel in the token's domain: a high-s copy of a valid signature is refused like the contract would (review
+    //    I4); the canonical one takes the order off the book now and closes it on the token at the next sync (an
+    //    `mtxCancelOrder` entry job).
+    let td = domain("SCaaS MetaToken", chain_id, token_a, uid);
     let high_s = {
-        let s = alice.sign_hash_sync(&cancel_digest(&d, ask_hash)).unwrap();
+        let s = alice.sign_hash_sync(&cancel_digest(&td, ask_hash)).unwrap();
         let n = U256::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
         let flipped = alloy::primitives::Signature::new(s.r(), n - s.s(), !s.v());
         format!("0x{}", alloy::hex::encode(flipped.as_bytes()))
     };
-    let (st, _) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"),
-        "signature": high_s})).await;
+    let (st, _) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"), "signature": high_s})).await;
     assert_eq!(st, 400);
     assert_eq!(venue.rows().await, before);
     let (st, body) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"),
-        "signature": sign_hash(&alice, cancel_digest(&d, ask_hash))})).await;
+        "signature": sign_hash(&alice, cancel_digest(&td, ask_hash))})).await;
     assert_eq!(st, 202, "{body}");
     assert!(venue.rows().await.is_empty());
     venue.sync_once().await.unwrap();
     drain(&mut s, &mut rx).await;
-    let out = p.call(TransactionRequest::default().to(dex).input(filledCall { h: ask_hash }.abi_encode().into())).await.unwrap();
-    assert_eq!(U256::abi_decode(&out).unwrap(), U256::from(100_000_000u64));
+    let pulled = |token: Address, h: B256| {
+        let rpc = rpc.clone();
+        async move {
+            let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
+            let out = p.call(TransactionRequest::default().to(token).input(IToken::pulledCall { orderHash: h }.abi_encode().into())).await.unwrap();
+            U256::abi_decode(&out).unwrap()
+        }
+    };
+    assert_eq!(pulled(token_a, ask_hash).await, U256::from(100_000_000u64), "closed on the token");
 
-    // 7. The watcher brings final DEX events to Odoo with its own cursor.
+    // 7. The watcher brings final DEX and token events to the client with its own cursor.
     while venue.watch_once().await.unwrap() {}
     let ev = state.lock().unwrap().dex_events.clone();
     let names: Vec<&str> = ev.iter().map(|e| e["event"].as_str().unwrap()).collect();
-    assert!(names.contains(&"OrderFilled") && names.contains(&"Matched") && names.contains(&"OrderCancelled"), "{names:?}");
-    let filled_alice = ev.iter().find(|e| e["event"] == "OrderFilled" && e["order_hash"] == format!("{ask_hash:#x}")).unwrap();
-    assert_eq!(filled_alice["dex_fee"], "80000");
+    assert!(names.contains(&"LegSettled") && names.contains(&"OrderCancelled"), "{names:?}");
+    let filled_alice = ev.iter().find(|e| e["event"] == "LegSettled" && e["order_hash"] == format!("{ask_hash:#x}")).unwrap();
+    assert_eq!((filled_alice["dex_fee"].as_str(), filled_alice["relayer_share"].as_str()), (Some("120000"), Some("60000")));
     assert_eq!(state.lock().unwrap().dex_trades.len(), 1);
 
-    // 8. A settle job that dies: Odoo marks its trade failed, sync hands both healthy sides back,
-    //    and they trade again as a NEW trade (no crossed book, no tag collision).
-    let ask3 = order(&alice, token_a, 10_000_000, token_b, 20_000_000, 7, relayer.address());
-    let bid3 = order(&bob, token_b, 20_000_000, token_a, 10_000_000, 8, relayer.address());
-    assert_eq!(place(ask3.clone(), &alice).await.1["status"], "resting");
-    assert_eq!(place(bid3.clone(), &bob).await.1["status"], "filled");
+    // 8. A settle job that dies: the client marks its trade failed, sync hands both healthy sides back and they
+    //    trade again as a NEW trade (no crossed book, no tag collision).
+    let ask3 = order(&alice, token_b, 10_000_000, 20_000_000, 1_000, 7, lane, dex);
+    let bid3 = order(&bob, token_a, 20_000_000, 10_000_000, 2_000, 8, lane, dex);
+    assert_eq!(place(token_a, ask3.clone(), &alice).await.1["status"], "resting");
+    assert_eq!(place(token_b, bid3.clone(), &bob).await.1["status"], "filled");
     let dead_tag = {
         let mut o = state.lock().unwrap();
         o.jobs.clear(); // the settle job never reaches the chain
         let t = o.dex_trades.last().unwrap().clone();
-        let row = |h: B256| {
-            let r = o.orders[&format!("{h:#x}")].clone();
-            json!({"order_hash": r["order_hash"], "order": r["order"], "signature": r["signature"],
-                   "remaining": r["remaining"], "seq": r["seq"]})
-        };
-        let f = json!({"tag": t["tag"], "maker": row(order_hash(&d, &ask3)), "taker": row(order_hash(&d, &bid3)),
-                       "maker_fill": t["maker_fill"], "taker_fill": t["taker_fill"]});
+        let row = |h: B256| row_of(&o.orders[&format!("{h:#x}")]);
+        let f = json!({"tag": t["tag"], "taker": {"row": row(hash(token_b, &bid3)), "fill": t["taker_fill"]},
+                       "makers": [{"row": row(hash(token_a, &ask3)), "fill": t["makers"][0]["fill"]}]});
         o.failed.push(f);
         t["tag"].clone()
     };
@@ -598,26 +645,24 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
     assert_ne!(last["tag"], dead_tag);
     assert!(venue.rows().await.is_empty(), "both sides traded again; nothing rests crossed");
     drain(&mut s, &mut rx).await;
-    assert_eq!(balance(&rpc, token_b, alice.address()).await, U256::from(79_920_000u64 + 20_000_000 - 20_000));
-    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(39_920_000u64 + 10_000_000 - 20_000));
-
-    // 9. A dead trade whose taker is closed in Odoo (null row, review I3): the maker alone goes back
-    //    to the book AND to Odoo, so a restart still has it.
-    let ask4 = order(&alice, token_a, 10_000_000, token_b, 20_000_000, 9, relayer.address());
-    let bid4 = order(&bob, token_b, 20_000_000, token_a, 10_000_000, 10, relayer.address());
-    let ask4_hash = format!("{:#x}", order_hash(&d, &ask4));
-    assert_eq!(place(ask4.clone(), &alice).await.1["status"], "resting");
-    assert_eq!(place(bid4.clone(), &bob).await.1["status"], "filled");
+    assert_eq!(balance(&rpc, token_b, alice.address()).await, alice_b0 + U256::from(119_880_000u64 + 20_000_000 - 20_000));
+    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(59_880_000u64 + 10_000_000 - 20_000));
+
+    // 9. A dead trade whose taker is closed in the client (null row, review I3): the maker alone goes back to the
+    //    book AND to the client, so a restart still has it.
+    let ask4 = order(&alice, token_b, 10_000_000, 20_000_000, 1_000, 9, lane, dex);
+    let bid4 = order(&bob, token_a, 20_000_000, 10_000_000, 2_000, 10, lane, dex);
+    let ask4_hash = format!("{:#x}", hash(token_a, &ask4));
+    assert_eq!(place(token_a, ask4.clone(), &alice).await.1["status"], "resting");
+    assert_eq!(place(token_b, bid4.clone(), &bob).await.1["status"], "filled");
     {
         let mut o = state.lock().unwrap();
         o.jobs.clear();
         let t = o.dex_trades.last().unwrap().clone();
         let r = o.orders[&ask4_hash].clone();
         assert_eq!(r["state"], "filled");
-        let row = json!({"order_hash": r["order_hash"], "order": r["order"], "signature": r["signature"],
-                         "remaining": r["remaining"], "seq": r["seq"]});
-        o.failed.push(json!({"tag": t["tag"], "maker": row, "taker": null,
-                             "maker_fill": t["maker_fill"], "taker_fill": t["taker_fill"]}));
+        o.failed.push(json!({"tag": t["tag"], "taker": {"row": null, "fill": t["taker_fill"]},
+                             "makers": [{"row": row_of(&r), "fill": t["makers"][0]["fill"]}]}));
     }
     venue.sync_once().await.unwrap();
     let rows = venue.rows().await;
@@ -627,6 +672,39 @@ async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
     assert_eq!((stored["state"].as_str(), stored["remaining"].as_str()), (Some("open"), Some("10000000")));
     let venue3 = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
     assert_eq!(venue3.rows().await, rows);
+
+    // 10. Cancel-all on the token's order lane (`InvalidateNonces` in A's domain, an `mtxInvalidateNonces` entry job).
+    let (st, body) = post("/v1/dex/cancel-all", json!({"chain": chain_id, "sellToken": token_a, "from": alice.address(),
+        "batch": "1", "minNonce": "21", "signature": sign_hash(&alice, invalidate_digest(&td, alice.address(), U256::from(1), U256::from(21)))})).await;
+    assert_eq!((st, body["orders"].as_u64()), (202, Some(1)), "{body}");
+    assert!(venue.rows().await.is_empty());
+    venue.sync_once().await.unwrap();
+    drain(&mut s, &mut rx).await;
+    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
+    let min = IToken::minNonceCall { from: alice.address(), batch: U256::from(1) }.abi_encode();
+    let out = p.call(TransactionRequest::default().to(token_a).input(min.into())).await.unwrap();
+    assert_eq!(U256::abi_decode(&out).unwrap(), U256::from(21));
+
+    // 11. An outside token (CTR-DEX-18, -22): dave's USDC order is a `DexOrder` in the DEX's domain, pulled through
+    //     the `DexPuller` he approved (never the DEX); alice's A order takes it.
+    let pull = {
+        let out = p.call(TransactionRequest::default().to(dex).input(pullerCall {}.abi_encode().into())).await.unwrap();
+        Address::abi_decode(&out).unwrap()
+    };
+    let _: Value = p.raw_request("anvil_setBalance".into(), (dave.address(), "0xde0b6b3a7640000")).await.unwrap();
+    send(&rpc, &dave, usdc, approveCall { spender: pull, value: U256::MAX }.abi_encode()).await;
+    let dd = domain("SCaaS Dex", chain_id, dex, uid);
+    let usd = order(&dave, token_a, 200_000_000, 100_000_000, 0, 30, lane, dex);
+    let usd_hash = dex_order_hash(&dd, usdc, &usd);
+    let (st, body) = post("/v1/dex/orders", json!({"chain": chain_id, "sellToken": usdc, "order": WireOrder::from_sol(&usd),
+        "signature": sign_hash(&dave, usd_hash)})).await;
+    assert_eq!((st, body["status"].as_str(), body["order_hash"].as_str()), (202, Some("resting"), Some(&*format!("{usd_hash:#x}"))), "{body}");
+    let take = order(&alice, usdc, 100_000_000, 200_000_000, 0, 31, lane, dex);
+    assert_eq!(place(token_a, take, &alice).await.1["status"], "filled");
+    drain(&mut s, &mut rx).await;
+    assert_eq!(balance(&rpc, usdc, alice.address()).await, U256::from(200_000_000u64));
+    assert_eq!(balance(&rpc, token_a, dave.address()).await, U256::from(100_000_000u64));
+    assert_eq!(balance(&rpc, usdc, dex).await + balance(&rpc, usdc, pull).await, U256::ZERO);
 }
 
 fn pay_job(payer: &PrivateKeySigner, dep: &Value, chain_id: u64, token: Address, id: i64, tag: &[u8]) -> Value {
diff --git a/scaas-node/tests/fuzz.rs b/scaas-node/tests/fuzz.rs
index e3cbccf..34c7743 100644
--- a/scaas-node/tests/fuzz.rs
+++ b/scaas-node/tests/fuzz.rs
@@ -68,14 +68,13 @@ proptest! {
         }
     }
 
-    /// Lệnh DEX (R35) từ body gateway / sổ Odoo: chuỗi bất kỳ ⇒ `Err`, không panic.
+    /// A DEX order (NODE-DEX-15) from a gateway body or the client's book: any strings ⇒ `Err`, never a panic.
     #[test]
-    fn dex_wire_order_never_panics(f in prop::collection::vec(prop_oneof!["0x[0-9a-fA-F]{0,70}", "[0-9]{0,90}", ".{0,20}"], 11),
-                                   ppm in any::<u32>(), flags in any::<u8>(), mode in any::<u8>()) {
-        let w = WireOrder { maker: f[0].clone(), taker: f[1].clone(), sell_token: f[2].clone(), buy_token: f[3].clone(),
-            sell_amount: f[4].clone(), buy_amount: f[5].clone(), nonce: f[6].clone(), expiry: f[7].clone(),
-            max_fee_ppm: ppm, flags, relayer: f[8].clone(), fee_mode: mode, fee: f[9].clone(),
-            fee_token: f[10].clone(), fee_recipient: f[0].clone() };
+    fn dex_wire_order_never_panics(f in prop::collection::vec(prop_oneof!["0x[0-9a-fA-F]{0,70}", "[0-9]{0,90}", ".{0,20}"], 12),
+                                   flags in any::<u8>()) {
+        let w = WireOrder { from: f[0].clone(), receive_token: f[1].clone(), amount: f[2].clone(), receive_amount: f[3].clone(),
+            min_fill: f[4].clone(), fee: f[5].clone(), relayer: f[6].clone(), dex: f[7].clone(), destination: f[8].clone(),
+            flags, batch: f[9].clone(), nonce: f[10].clone(), valid_until: f[11].clone() };
         let _ = w.to_sol();
     }
 }
``````


### Task 4: The money-safety guard (call table, `chainUid()` binding, selector tables, gas), the mutation probe

`src/guard.rs` (new) holds the pure rules and the cached chain reads (N2–N6). The submitter runs `Guard::check` before
every simulation and signature and sizes gas with `guard::gas` (`mtxSettle` by simulation, the ERC-1271 floor for a
contract signer); a simulated `MinNonceNotIncreasing` on an invalidation is consumed `already_invalidated`.
`Submitter::start` reads `Chain::uid()` and refuses to run a lane whose pinned `chain_uid` is not the RPC's block 0.
`ChainCfg` gains `chain_uid`, `account_factory`, `token_factory`; `Chain` gains `uid()`, `call_view`, `call_with_gas`,
`has_code`; `Work` gains `entry`; the EVM adapter's runner uses the same guard and gas. The e2e payment test adds the
refusals on a real chain (a `call` job `transfer` on the token, a meta-tx to an unbound address, a `call`-struct
`transfer`) and a `cancelNonce(99)` self-call that lands.

**Files:** create `scaas-node/src/guard.rs`; modify `scaas-node/src/{lib,config,chain,submit,gateway,dex}.rs`,
`scaas-node/src/adapters/{evm,hedera}.rs`, `scaas-node/tests/e2e.rs`.

- [ ] **Step 1: Apply the diff below.**
- [ ] **Step 2: Gates.** `cargo test --lib` 254 passed; `cargo test --test mesh_vectors --test fuzz` 4 + 1 passed; clippy
  clean; e2e 4/4; e2e_hedera 1/1.
- [ ] **Step 3: Mutation probe** (the money-safety checks; each mutant is applied alone, `cargo test --lib` must fail;
  a compile error counts as not viable, never as killed). Save as `/tmp/p5-mutate.py` and run
  `python3 /tmp/p5-mutate.py "$PWD/scaas-node"`: expected `39/39 killed`.
  ```python
  #!/usr/bin/env python3
  """P5 mutation probe of the node's money-safety checks: apply each mutant, run the lib tests, restore.
  A mutant is killed when the tests fail (a compile error is reported as NOT VIABLE, never as killed)."""
  import os
  import subprocess
  import sys

  NODE = sys.argv[1]
  CAPPED = '/home/ha/work/ainative/scaas/scripts/capped'
  ENV = dict(os.environ, CARGO_TARGET_DIR='/home/ha/work/ainative/scaas/scaas-node/target')

  M = [
      # guard.rs: call table and target rules (PAY-FIX2, NODE-JOB-01/-19, NODE-GW-07)
      ('src/guard.rs', '    f.bound\n        && !f.token\n', '    true\n        && !f.token\n', 'a call target need not be bound to this chain'),
      ('src/guard.rs', '        && !f.token\n        && !f.token_factory\n', '        && !f.token_factory\n', 'a registered token may be a call target'),
      ('src/guard.rs', '        && !f.token_factory\n        && match', '        && match', 'the token factory may be a call target'),
      ('src/guard.rs', 'Rule::AccountFactory => f.account_factory,', 'Rule::AccountFactory => true,', 'deploy on any contract'),
      ('src/guard.rs', 'Rule::Dex => f.dex,', 'Rule::Dex => true,', 'mtxSettle on any contract'),
      ('src/guard.rs', '(SEL_MTX_SETTLE, "SCaaSDex.mtxSettle", Rule::Dex)', '(SEL_MTX_SETTLE, "SCaaSDex.mtxSettle", Rule::SelfAuth)', 'mtxSettle row loses its DEX rule'),
      ('src/guard.rs', '([0xb5, 0x34, 0xf2, 0x74], "MandateWallet.mtxRevoke"', '([0xa9, 0x05, 0x9c, 0xbb], "MandateWallet.mtxRevoke"', 'a transfer selector in the call table'),
      ('src/guard.rs', '            if !ENTRIES.contains(&sel) {', '            if false {', 'any selector as an entry'),
      ('src/guard.rs', '            self.require_bound(chain, w.to).await?;\n            if let Some', '            if let Some', 'a meta-tx target need not be bound'),
      ('src/guard.rs', '            return self.require_bound(chain, w.to).await;', '            return Ok(());', 'an entry target need not be bound'),
      ('src/guard.rs', '                self_call_ok(&t, &m.data, m.mode).map_err(Refusal::Policy)?;', '                let _ = self_call_ok(&t, &m.data, m.mode);', 'the selector table is not enforced'),
      # guard.rs: self-call intake (NODE-JOB-20)
      ('src/guard.rs', '''        return Err(format!("SELECTOR_NOT_ALLOWED: 0x{} is not on the contract's allowlist", alloy::hex::encode(sel)));''', '        return Ok(());', 'an unlisted selector passes'),
      ('src/guard.rs', '(mode & MODE_FEE_MASK) >> 4 == 1', '(mode & MODE_FEE_MASK) >> 4 == 2', 'PERCENT allowed on ABSOLUTE'),
      ('src/guard.rs', '    if mode & !t.supported != 0 {', '    if false {', 'supportedModes ignored'),
      ('src/guard.rs', 'data.len() < 36 + 32 * usize::from(arg)', 'data.len() < 4', 'AMOUNT basis argument not required'),
      ('src/guard.rs', '    if class != FEE_CLASS_ABSOLUTE && class != FEE_CLASS_AMOUNT {', '    if false {', 'unknown fee class accepted'),
      # guard.rs: simulation gating and gas
      ('src/guard.rs', '    if contract_signer { g.max(ERC1271_FLOOR) } else { g }', '    g', 'no ERC-1271 floor'),
      ('src/guard.rs', '21_000 + 400_000 * 64 / 63 + 5_000', '21_000 + 50_000 * 64 / 63 + 5_000', 'the floor uses the 50 k cap'),
      ('src/guard.rs', 'v.iter().all(|x| *x)', 'v.iter().any(|x| *x)', 'one settled settlement is enough'),
      ('src/guard.rs', '(g < max).then(|| g.saturating_add(g / 2).min(max))', '(g < max).then(|| g.saturating_add(g / 2))', 'settle gas past max_gas_per_tx'),
      ('src/guard.rs', "    data.get(..4) == Some(&SEL_MTX_INVALIDATE_NONCES[..]) && reason", '    reason', 'any MinNonceNotIncreasing is success'),
      ('src/guard.rs', '    if !w.entry && w.meta.is_none() && w.data.get(..4) == Some(&SEL_MTX_SETTLE[..]) {', '    if false {', 'mtxSettle gas not sized by simulation'),
      ('src/guard.rs', '        Some(m) => chain.has_code(m.from).await.map_err(|e| SimError::Transport(format!("eth_getCode: {e:#}")))?,', '        Some(_) => false,', 'contract signer not detected'),
      # submit.rs: the wiring
      ('src/submit.rs', '        match self.guard.check(&self.chain, &w).await {', '        match Ok::<(), Refusal>(()) {', 'the submitter skips the guard'),
      ('src/submit.rs', '        if guard::already_invalidated(&w.data, &reason) {', '        if false {', 'an invalidation in force is dead'),
      # chain.rs: NODE-GW-07 at start
      ('src/chain.rs', '(Some(p), Some(g)) if p != g => Err', '(Some(p), Some(g)) if p != g && false => Err', 'a wrong chain_uid pin accepted'),
      # dex.rs: the settlement mirror and intake (NODE-DEX-15, -16)
      ('src/dex.rs', '    o.minFill.max(o.amount - o.amount / U256::from(2u8))', '    o.minFill', 'no 50 % floor'),
      ('src/dex.rs', '                if x < r.remaining && x < min_fill(&r.order) {', '                if false {', 'a maker filled below its minimum'),
      ('src/dex.rs', '        let settles = !makers.is_empty() && (taken >= min_fill(&t.order) || taken == t.remaining);', '        let settles = !makers.is_empty();', 'a taker filled below its minimum'),
      ('src/dex.rs', '        && y == maker_receives(m, x)\n', '', 'the maker receive is not the ceiling'),
      ('src/dex.rs', '        if o.relayer != relayer {', '        if false {', 'not home-bound'),
      ('src/dex.rs', '        if o.dex != dex {', '        if false {', 'an unlisted DEX (NODE-DEX-16)'),
      ('src/dex.rs', '        if need > fundable {', '        if false {', 'committed balance ignored'),
      ('src/dex.rs', '        if o.flags & !(FLAG_IOC | FLAG_LISTED_POOLS) != 0 {', '        if o.flags & !(FLAG_IOC | FLAG_LISTED_POOLS | FLAG_ESCROW) != 0 {', 'ESCROW accepted'),
      ('src/dex.rs', '        if t.order.flags & FLAG_IOC != 0 || crossed {', '        if t.order.flags & FLAG_IOC != 0 {', 'a remainder rests crossed'),
      ('src/dex.rs', '                if r.order.from == t.order.from || r.order.fee < U256::from(maker_ppm) {', '                if r.order.fee < U256::from(maker_ppm) {', 'self-trade'),
      ('src/dex.rs', '        let fee_ok = if rests { maker_ok && (taker_ok || !self.would_cross(sell, o)) } else { taker_ok };', '        let fee_ok = true;', 'fee rates by role ignored'),
      ('src/dex.rs', '            && m.order.from != t.order.from\n', '', 'settlement mirror: self-trade'),
      ('src/dex/venue.rs', '    if data.is_empty() {\n        return "out_of_gas".into();', '    if false {\n        return "out_of_gas".into();', 'an empty MatchFailed blames an order'),
  ]


  def run_tests():
      r = subprocess.run([CAPPED, 'cargo', 'test', '--lib', '-q'], cwd=NODE, env=ENV, capture_output=True, text=True)
      out = r.stdout + r.stderr
      if 'error[E' in out or 'error: could not compile' in out:
          return 'not viable'
      return 'killed' if r.returncode != 0 else 'SURVIVED'


  results = []
  for path, old, new, what in M:
      p = os.path.join(NODE, path)
      src = open(p).read()
      if src.count(old) != 1:
          results.append(('MISSING', path, what))
          print('MISSING', path, what, flush=True)
          continue
      open(p, 'w').write(src.replace(old, new))
      try:
          res = run_tests()
      finally:
          open(p, 'w').write(src)
      results.append((res, path, what))
      print(res, path, what, flush=True)
  killed = sum(r[0] == 'killed' for r in results)
  print(f'{killed}/{len(results)} killed')
  ```
- [ ] **Step 4: Commit** `P5 T4: money-safety guard before every simulation and signature (call table, chainUid binding, selector tables, settle gas, ERC-1271 floor)`.

``````diff
diff --git a/scaas-node/src/adapters/evm.rs b/scaas-node/src/adapters/evm.rs
index 2342e9d..5b21388 100644
--- a/scaas-node/src/adapters/evm.rs
+++ b/scaas-node/src/adapters/evm.rs
@@ -16,6 +16,7 @@ use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Signed, TxStatus};
 use crate::chain::{Chain, SimError};
 use crate::config::ChainCfg;
 use crate::finality::{quorum_ok, safe_head, Mode};
+use crate::guard::{self, Guard};
 use crate::indexer::encode_event;
 use crate::odoo::Job;
 use crate::submit::work_from_job;
@@ -30,6 +31,8 @@ pub struct EvmAdapter {
     max_gas: u64,
     /// Token đã đăng ký (làm mới từ `node_config`); event của contract lạ không bao giờ gửi Odoo.
     pub tokens: Arc<RwLock<Vec<Address>>>,
+    /// PAY-FIX2, NODE-GW-07, NODE-JOB-20: checked before every simulation.
+    guard: Guard,
 }
 
 impl EvmAdapter {
@@ -44,6 +47,7 @@ impl EvmAdapter {
             .collect();
         let mode = if cfg.finality.mode == "tag" { Mode::Tag } else { Mode::Depth(cfg.finality.depth) };
         Ok(Self {
+            guard: Guard::new(cfg, tokens.clone()),
             key: cfg.chain_key(),
             family: if cfg.family == "hedera" { Family::Hedera } else { Family::Evm },
             chains,
@@ -77,15 +81,13 @@ impl ChainAdapter for EvmAdapter {
     async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
         let w = work_from_job(job).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
         let chain = self.lane(lane).map_err(|e| SimError::Transport(e.to_string()))?;
-        let gas = chain.simulate(w.to, w.data.clone()).await?;
-        if gas > self.max_gas {
-            return Err(SimError::Revert(format!("gas {gas} above max_gas_per_tx")));
-        }
+        self.guard.check(chain, &w).await?;
+        let gas = guard::gas(chain, &w, self.max_gas).await?;
         Ok(Built {
             job_id: job.id,
             body: w.data.to_vec(),
             valid_until: w.valid_until,
-            meta: json!({"to": format!("{:#x}", w.to), "gas": gas + gas / 5}),
+            meta: json!({"to": format!("{:#x}", w.to), "gas": gas}),
         })
     }
 
diff --git a/scaas-node/src/adapters/hedera.rs b/scaas-node/src/adapters/hedera.rs
index 388d2fd..29661cf 100644
--- a/scaas-node/src/adapters/hedera.rs
+++ b/scaas-node/src/adapters/hedera.rs
@@ -296,6 +296,8 @@ mod tests {
         let ok = |r: Value| json!({"jsonrpc": "2.0", "id": id, "result": r});
         axum::Json(match b["method"].as_str().unwrap_or_default() {
             "eth_getBalance" => ok(json!(n.balance)),
+            "eth_getBlockByNumber" => ok(Value::Null),
+            "eth_getCode" => ok(json!("0x")),
             "eth_call" => ok(json!(format!("0x{:064x}", n.mtx_nonce))),
             "eth_estimateGas" => ok(json!("0x186a0")),
             "eth_gasPrice" => ok(json!(format!("0x{GAS_PRICE:x}"))),
@@ -346,6 +348,8 @@ mod tests {
         tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
         let mut cfg: ChainCfg = toml::from_str("family = \"hedera\"\nevm_chain_number = 296\nrpc_urls = [\"http://x\"]\n").unwrap();
         cfg.rpc_urls = vec![url.clone()];
+        // every `eth_call` of the fake answers the same word: `chainUid()` too, so the pinned chain_uid is that word
+        cfg.chain_uid = Some(B256::from(U256::from(s.lock().unwrap().mtx_nonce)));
         let signer = LocalSigner::new(crate::signer::Curve::Secp256k1, &[7u8; 32]).unwrap();
         let a = HederaAdapter::from_cfg(&cfg, &[signer]).unwrap();
         let oc = crate::config::OdooCfg { url, database: "t".into(), relay_api_key_env: String::new(), indexer_api_key_env: String::new() };
diff --git a/scaas-node/src/chain.rs b/scaas-node/src/chain.rs
index 33912e7..402d94c 100644
--- a/scaas-node/src/chain.rs
+++ b/scaas-node/src/chain.rs
@@ -52,6 +52,9 @@ pub struct Chain {
     providers: Vec<DynProvider>,
     wallet: EthereumWallet,
     address: Address,
+    /// `chain_uid` from the config, checked against the RPC's block 0 (NODE-GW-07).
+    pinned_uid: Option<B256>,
+    uid: tokio::sync::OnceCell<B256>,
 }
 
 impl Chain {
@@ -70,7 +73,14 @@ impl Chain {
         if providers.is_empty() {
             return Err(anyhow!("chain {}: no rpc_urls", cfg.evm_chain_number));
         }
-        Ok(Self { number: cfg.evm_chain_number, providers, wallet: EthereumWallet::from(signer), address })
+        Ok(Self {
+            number: cfg.evm_chain_number,
+            providers,
+            wallet: EthereumWallet::from(signer),
+            address,
+            pinned_uid: cfg.chain_uid,
+            uid: Default::default(),
+        })
     }
 
     pub fn primary(&self) -> &DynProvider {
@@ -97,6 +107,39 @@ impl Chain {
         self.primary().estimate_gas(tx).await.map_err(|e| classify(&e))
     }
 
+    /// This chain's `chain_uid`: the RPC's block 0 hash, which must equal the configured `chain_uid` when one is set
+    /// (a pruned RPC without block 0 trusts the configured one). Read once; an error is not remembered.
+    pub async fn uid(&self) -> Result<B256> {
+        self.uid
+            .get_or_try_init(|| async {
+                match (self.pinned_uid, Self::block_hash(self.primary(), 0).await) {
+                    (Some(p), Some(g)) if p != g => Err(anyhow!("chain {}: RPC block 0 {g:#x} is not chain_uid {p:#x}", self.number)),
+                    (Some(p), _) | (None, Some(p)) => Ok(p),
+                    (None, None) => Err(anyhow!("chain {}: the RPC gives no block 0 hash; set chain_uid", self.number)),
+                }
+            })
+            .await
+            .copied()
+    }
+
+    /// A view call; a revert is the contract's answer (`SimError::Revert`), anything else the transport's.
+    pub async fn call_view<C: SolCall>(&self, to: Address, call: C) -> std::result::Result<C::Return, SimError> {
+        let tx = TransactionRequest::default().with_to(to).with_input(call.abi_encode());
+        let out = self.primary().call(tx).await.map_err(|e| classify(&e))?;
+        C::abi_decode_returns(&out).map_err(|e| SimError::Revert(format!("decode: {e}")))
+    }
+
+    /// `eth_call` from the lane with exactly `gas` (sizing `mtxSettle`, `guard::settle_gas`).
+    pub async fn call_with_gas(&self, to: Address, data: Bytes, gas: u64) -> std::result::Result<Bytes, SimError> {
+        let tx = TransactionRequest::default().with_from(self.address).with_to(to).with_input(data).with_gas_limit(gas);
+        self.primary().call(tx).await.map_err(|e| classify(&e))
+    }
+
+    /// `who` has code (a contract signer: ERC-1271, `guard::ERC1271_FLOOR`).
+    pub async fn has_code(&self, who: Address) -> Result<bool> {
+        Ok(!self.primary().get_code_at(who).await?.is_empty())
+    }
+
     pub async fn fees(&self) -> Result<(u128, u128)> {
         let est = self.primary().estimate_eip1559_fees().await?;
         Ok((est.max_fee_per_gas.max(1), est.max_priority_fee_per_gas))
@@ -183,3 +226,41 @@ impl Chain {
         p.get_block_by_number(BlockNumberOrTag::Number(n)).await.ok().flatten().map(|b| b.header.hash)
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use serde_json::{json, Value};
+
+    /// An RPC whose block 0 is the recorded Hedera testnet block (any block will do: only its hash is read).
+    async fn rpc() -> (String, B256) {
+        let block: Value = serde_json::from_str::<Value>(include_str!("../tests/vectors/hedera_testnet.json")).unwrap()["block"].clone();
+        let hash = block["hash"].as_str().unwrap().parse().unwrap();
+        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
+            let block = block.clone();
+            async move { axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": block})) }
+        }));
+        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
+        let url = format!("http://{}", l.local_addr().unwrap());
+        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
+        (url, hash)
+    }
+
+    fn chain(url: &str, pin: Option<B256>) -> Chain {
+        let cfg = ChainCfg { evm_chain_number: 296, rpc_urls: vec![url.into()], chain_uid: pin, ..Default::default() };
+        Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap()
+    }
+
+    /// NODE-GW-07: the chain's `chain_uid` is its block 0 hash; a configured one that differs refuses the chain.
+    #[tokio::test]
+    async fn chain_uid_is_block_zero_and_a_wrong_pin_is_refused() {
+        let (url, genesis) = rpc().await;
+        assert_eq!(chain(&url, None).uid().await.unwrap(), genesis);
+        assert_eq!(chain(&url, Some(genesis)).uid().await.unwrap(), genesis);
+        assert!(chain(&url, Some(B256::repeat_byte(1))).uid().await.is_err());
+        // a pruned RPC (no block 0) trusts the pin, and without one there is no chain_uid
+        let dead = "http://127.0.0.1:9";
+        assert_eq!(chain(dead, Some(B256::repeat_byte(1))).uid().await.unwrap(), B256::repeat_byte(1));
+        assert!(chain(dead, None).uid().await.is_err());
+    }
+}
diff --git a/scaas-node/src/config.rs b/scaas-node/src/config.rs
index 5b99d6a..2e2fdf7 100644
--- a/scaas-node/src/config.rs
+++ b/scaas-node/src/config.rs
@@ -3,7 +3,7 @@ use std::path::Path;
 use crate::keys::{self, SecretSource, Seed};
 use crate::signer::LocalSigner;
 
-use alloy::primitives::Address;
+use alloy::primitives::{Address, B256};
 use anyhow::{bail, Context, Result};
 use serde::{Deserialize, Serialize};
 
@@ -267,6 +267,17 @@ pub struct ChainCfg {
     pub finality: FinalityCfg,
     #[serde(default)]
     pub dex: Option<Address>,
+    /// `chain_uid` (genesis hash, `smartcontracts/evm/chain-uids.json`): the salt of every SCaaS domain on this chain
+    /// (NODE-GW-07). Set ⇒ the RPC's block 0 hash must equal it (a pruned RPC that has no block 0 trusts it); unset ⇒
+    /// the RPC's block 0 hash.
+    #[serde(default)]
+    pub chain_uid: Option<B256>,
+    /// The chain's `SmartKeyAccountFactory`: the target of the call-table row `deploy` (NODE-JOB-19).
+    #[serde(default)]
+    pub account_factory: Option<Address>,
+    /// The token factory (`OpenFactory`): never a `call` target (NODE-JOB-01).
+    #[serde(default)]
+    pub token_factory: Option<Address>,
     /// Ví lạnh nhận phí của meta-tx không ràng buộc `feeRecipient` (R84, EVM/Hedera); không phải khoá lane.
     /// Không đặt ⇒ ghi 0: contract trả phí cho `msg.sender` (lane gửi).
     #[serde(default)]
@@ -367,6 +378,9 @@ impl Default for ChainCfg {
             params: Default::default(),
             finality: default_finality(),
             dex: None,
+            chain_uid: None,
+            account_factory: None,
+            token_factory: None,
             fee_recipient: None,
             poll_ms: default_poll(),
             stuck_after_secs: default_stuck(),
diff --git a/scaas-node/src/dex.rs b/scaas-node/src/dex.rs
index 1a1a539..921263d 100644
--- a/scaas-node/src/dex.rs
+++ b/scaas-node/src/dex.rs
@@ -996,6 +996,11 @@ mod tests {
         assert!(!limits_ok(&m, &t, U256::from(1), U256::from(4)));
         assert!(!limits_ok(&m, &t, U256::from(4), U256::from(14)), "overfill");
         assert!(!limits_ok(&m, &t, U256::from(3), U256::from(9)), "y is the maker's ceiling receive, not less");
+        // a taker that would pay more than the maker's ceiling: within both price limits, yet the DEX computes the
+        // maker's receive itself (FillMismatch), so the leg is refused here too
+        let rich = Resting { order: bid(2, 12, 3, 1), remaining: U256::from(12), ..t.clone() };
+        assert!(limits_ok(&m, &rich, U256::from(3), U256::from(10)));
+        assert!(!limits_ok(&m, &rich, U256::from(3), U256::from(11)));
         let s = |makers: Vec<(Resting, U256, U256)>, fill: u64| PlannedSettlement {
             tag: B256::ZERO, market_id: 1, taker: t.clone(), taker_fill: U256::from(fill), makers };
         assert!(settlement_ok(&s(vec![(m.clone(), U256::from(3), U256::from(10))], 10)));
diff --git a/scaas-node/src/gateway.rs b/scaas-node/src/gateway.rs
index 99ac88f..0dad101 100644
--- a/scaas-node/src/gateway.rs
+++ b/scaas-node/src/gateway.rs
@@ -155,7 +155,7 @@ fn work_of(r: SignedReq, fee_recipient: Option<Address>) -> Result<Work, Reply>
     }
     let valid_until = m.valid_until().saturating_to();
     let meta = Some(MetaRef::of(r.token, &m, None));
-    Ok(Work { job_id: None, to: r.token, data: m.calldata(sig), valid_until, meta })
+    Ok(Work { job_id: None, to: r.token, data: m.calldata(sig), valid_until, meta, entry: false })
 }
 
 async fn post_metatx(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Reply {
diff --git a/scaas-node/src/guard.rs b/scaas-node/src/guard.rs
new file mode 100644
index 0000000..8fe6314
--- /dev/null
+++ b/scaas-node/src/guard.rs
@@ -0,0 +1,415 @@
+//! Money safety before every simulation and signature (PAY-FIX2, NODE-JOB-01, -19, -20, NODE-GW-07). A lane is
+//! `msg.sender` of everything it signs, and it holds fee income in tokens, so:
+//!
+//! - a `call` job runs only when its selector is a row of the call table and its target meets the row's rule —
+//!   never a registered token or the token factory (a `transfer` of the lane's own balance is no row);
+//! - a token's order entry (`mtxCancelOrder`, `mtxInvalidateNonces`, `mtxWrap`, a `metatx` job naming its `entry`)
+//!   runs only on a contract bound to this chain;
+//! - a meta-transaction runs only on a contract bound to this chain (`chainUid()`, the salt every signature on it
+//!   commits to), and a self-call only with a selector, fee mode and mode bits the contract's published allowlist
+//!   accepts (`mtxSelectors()`, `supportedModes()`);
+//! - `mtxSettle` gas is sized by a simulation that settles every planned settlement (success is not monotonic in gas,
+//!   P2b-2), and a contract signer's meta-tx gets at least the ERC-1271 floor (P1b note c).
+//!
+//! Pure rules first (unit- and mutation-tested), then the cached chain reads (`Guard`).
+use std::collections::{HashMap, HashSet};
+use std::sync::{Arc, Mutex, RwLock};
+
+use alloy::primitives::{Address, Bytes};
+use alloy::sol_types::SolValue;
+
+use crate::abi::IToken;
+use crate::chain::{Chain, SimError};
+use crate::config::ChainCfg;
+use crate::metatx::{Mtx, MODE_FEE_MASK};
+use crate::submit::Work;
+
+pub const SEL_MTX_SETTLE: [u8; 4] = [0xb0, 0x95, 0x5d, 0xd6];
+pub const SEL_MTX_INVALIDATE_NONCES: [u8; 4] = [0xdb, 0xac, 0x32, 0xd0];
+pub const SEL_MTX_CANCEL_ORDER: [u8; 4] = [0x93, 0xcb, 0x3e, 0x81];
+pub const SEL_MTX_WRAP: [u8; 4] = [0x3e, 0xd1, 0x8b, 0xa8];
+
+/// What a call-table row requires of its target (job-api.md §11).
+#[derive(Debug, Clone, Copy, PartialEq, Eq)]
+pub enum Rule {
+    /// The chain's `SmartKeyAccountFactory` (`account_factory`).
+    AccountFactory,
+    /// Self-authenticating (`SmartKeyAccount`, `MandateWallet`): any contract bound to this chain that is not a
+    /// registered token or the token factory; the target checks the owner's or delegate's signature.
+    SelfAuth,
+    /// A DEX on the chain's DEX list (`dex`), bound to this chain.
+    Dex,
+}
+
+/// The call table as built in P5: the rows whose contracts exist (`cast sig` of the Solidity signatures; pinned
+/// against the KAT calldata). `mtxExecuteAsOwner` is one selector on `SmartKeyAccount` and `MandateWallet`, so it takes
+/// the wallet's rule. Every other selector is refused.
+pub const CALL_TABLE: [([u8; 4], &str, Rule); 10] = [
+    ([0x45, 0x9b, 0x5b, 0x50], "SmartKeyAccountFactory.deploy", Rule::AccountFactory),
+    ([0xfd, 0xf2, 0xd3, 0x38], "mtxExecuteAsOwner", Rule::SelfAuth),
+    ([0x3a, 0x5b, 0x07, 0x08], "HederaMandateWallet.mtxExecuteAsOwnerRaw", Rule::SelfAuth),
+    ([0x1d, 0xef, 0xeb, 0x10], "MandateWallet.mtxPayUnderMandate", Rule::SelfAuth),
+    ([0xb5, 0x34, 0xf2, 0x74], "MandateWallet.mtxRevoke", Rule::SelfAuth),
+    (SEL_MTX_SETTLE, "SCaaSDex.mtxSettle", Rule::Dex),
+    ([0x1e, 0x69, 0xbc, 0xde], "SCaaSDex.mtxExchange", Rule::Dex),
+    ([0xb2, 0x1f, 0xe8, 0xbc], "SCaaSDex.mtxExchangeVia", Rule::Dex),
+    ([0x2d, 0xe6, 0x21, 0xd2], "SCaaSDex.mtxCancelOrders", Rule::Dex),
+    (SEL_MTX_INVALIDATE_NONCES, "SCaaSDex.mtxInvalidateNonces", Rule::Dex),
+];
+
+/// The token entries a `metatx` job may name (job-api.md, order and wrap entries).
+pub const ENTRIES: [[u8; 4]; 3] = [SEL_MTX_CANCEL_ORDER, SEL_MTX_INVALIDATE_NONCES, SEL_MTX_WRAP];
+
+/// 21 000 intrinsic + the 400 k `SmartKeyAccount` ERC-1271 cap the contract must still hold at the call (×64/63)
+/// + `SigCheck`'s 5 000 margin (P1b note c): a contract signer's meta-tx never gets less.
+pub const ERC1271_FLOOR: u64 = 21_000 + 400_000 * 64 / 63 + 5_000;
+
+const FEE_CLASS_ABSOLUTE: u8 = 1;
+const FEE_CLASS_AMOUNT: u8 = 2;
+
+pub fn row(sel: [u8; 4]) -> Option<(&'static str, Rule)> {
+    CALL_TABLE.iter().find(|r| r.0 == sel).map(|r| (r.1, r.2))
+}
+
+/// What the node knows of a `call` target.
+#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
+pub struct Facts {
+    pub token: bool,
+    pub token_factory: bool,
+    pub account_factory: bool,
+    pub dex: bool,
+    /// `chainUid()` equals this chain's (NODE-GW-07).
+    pub bound: bool,
+}
+
+pub fn allowed(rule: Rule, f: &Facts) -> bool {
+    f.bound
+        && !f.token
+        && !f.token_factory
+        && match rule {
+            Rule::AccountFactory => f.account_factory,
+            Rule::SelfAuth => true,
+            Rule::Dex => f.dex,
+        }
+}
+
+/// A contract's published allowlist: `(selector, fee class, amount argument)` and `supportedModes()`.
+#[derive(Debug, Clone, Default, PartialEq, Eq)]
+pub struct Table {
+    pub rows: Vec<([u8; 4], u8, u8)>,
+    pub supported: u32,
+}
+
+/// NODE-JOB-20 intake of a self-call, as `MetaTxBase._checkCall` decides it, before any simulation: the selector is
+/// allowlisted, an `AMOUNT` selector carries its basis argument, an `ABSOLUTE` selector takes no `PERCENT` fee, and
+/// the mode has no bit the contract does not support. (The static ABI length is the contract's own check.)
+pub fn self_call_ok(t: &Table, data: &[u8], mode: u32) -> Result<(), String> {
+    let Some(sel) = data.get(..4) else { return Err("SELECTOR_NOT_ALLOWED: data shorter than a selector".into()) };
+    let Some(&(_, class, arg)) = t.rows.iter().find(|r| r.0 == sel) else {
+        return Err(format!("SELECTOR_NOT_ALLOWED: 0x{} is not on the contract's allowlist", alloy::hex::encode(sel)));
+    };
+    if class != FEE_CLASS_ABSOLUTE && class != FEE_CLASS_AMOUNT {
+        return Err("SELECTOR_NOT_ALLOWED: unknown fee class".into());
+    }
+    if class == FEE_CLASS_AMOUNT && data.len() < 36 + 32 * usize::from(arg) {
+        return Err("SELECTOR_NOT_ALLOWED: data shorter than its fee basis".into());
+    }
+    if class == FEE_CLASS_ABSOLUTE && (mode & MODE_FEE_MASK) >> 4 == 1 {
+        return Err("SELECTOR_NOT_ALLOWED: a PERCENT fee on an ABSOLUTE selector".into());
+    }
+    if mode & !t.supported != 0 {
+        return Err(format!("SELECTOR_NOT_ALLOWED: mode {mode:#x} outside supportedModes {:#x}", t.supported));
+    }
+    Ok(())
+}
+
+/// The gas limit of a simulated estimate: +20 %, and at least the ERC-1271 floor for a contract signer.
+pub fn gas_limit(estimate: u64, contract_signer: bool) -> u64 {
+    let g = estimate.saturating_add(estimate / 5);
+    if contract_signer { g.max(ERC1271_FLOOR) } else { g }
+}
+
+/// `mtxSettle` returned `ok` for every settlement it was given.
+pub fn settled_all(ret: &[u8]) -> bool {
+    <Vec<bool> as SolValue>::abi_decode(ret).is_ok_and(|v| !v.is_empty() && v.iter().all(|x| *x))
+}
+
+/// The next gas to try for `mtxSettle`: ×1.5, capped at `max`; `None` once at the cap.
+pub fn next_gas(g: u64, max: u64) -> Option<u64> {
+    (g < max).then(|| g.saturating_add(g / 2).min(max))
+}
+
+/// `mtxInvalidateNonces` (token or DEX) whose simulation says the lane is already at or past the asked minimum
+/// (`MinNonceNotIncreasing`): what it was sent for already holds, so the job is done, never dead (MT-8).
+pub fn already_invalidated(data: &[u8], reason: &str) -> bool {
+    data.get(..4) == Some(&SEL_MTX_INVALIDATE_NONCES[..]) && reason.starts_with("MinNonceNotIncreasing(")
+}
+
+/// Why the guard refused: a rule (the job is dead with this reason) or an unreadable chain (try again).
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub enum Refusal {
+    Policy(String),
+    Transport(String),
+}
+
+impl From<Refusal> for SimError {
+    fn from(r: Refusal) -> Self {
+        match r {
+            Refusal::Policy(s) => SimError::Revert(s),
+            Refusal::Transport(s) => SimError::Transport(s),
+        }
+    }
+}
+
+/// The chain reads behind the rules, cached: implementations are immutable, so a contract's `chainUid()` and
+/// allowlist never change (a contract that is not bound yet is asked again).
+pub struct Guard {
+    pub tokens: Arc<RwLock<Vec<Address>>>,
+    token_factory: Option<Address>,
+    account_factory: Option<Address>,
+    dexes: Vec<Address>,
+    bound: Mutex<HashSet<Address>>,
+    tables: Mutex<HashMap<Address, Arc<Table>>>,
+}
+
+impl Guard {
+    pub fn new(cfg: &ChainCfg, tokens: Arc<RwLock<Vec<Address>>>) -> Self {
+        Self {
+            tokens,
+            token_factory: cfg.token_factory,
+            account_factory: cfg.account_factory,
+            dexes: cfg.dex.into_iter().collect(),
+            bound: Default::default(),
+            tables: Default::default(),
+        }
+    }
+
+    pub async fn check(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
+        if w.meta.is_some() {
+            self.require_bound(chain, w.to).await?;
+            if let Some((Mtx::Call(m), _)) = Mtx::from_calldata(&w.data) {
+                let t = self.table(chain, w.to).await?;
+                self_call_ok(&t, &m.data, m.mode).map_err(Refusal::Policy)?;
+            }
+            return Ok(());
+        }
+        let sel: [u8; 4] = match w.data.get(..4) {
+            Some(s) => s.try_into().expect("4 bytes"),
+            None => return Err(Refusal::Policy("CALL_TARGET_REFUSED: no selector".into())),
+        };
+        if w.entry {
+            if !ENTRIES.contains(&sel) {
+                return Err(Refusal::Policy("CALL_TARGET_REFUSED: not an order or wrap entry".into()));
+            }
+            return self.require_bound(chain, w.to).await;
+        }
+        let Some((name, rule)) = row(sel) else {
+            return Err(Refusal::Policy(format!("CALL_TARGET_REFUSED: 0x{} is not in the call table", alloy::hex::encode(sel))));
+        };
+        let facts = Facts {
+            token: self.tokens.read().map(|t| t.contains(&w.to)).unwrap_or(true),
+            token_factory: self.token_factory == Some(w.to),
+            account_factory: self.account_factory == Some(w.to),
+            dex: self.dexes.contains(&w.to),
+            bound: self.bound(chain, w.to).await?,
+        };
+        if allowed(rule, &facts) {
+            Ok(())
+        } else {
+            Err(Refusal::Policy(format!("CALL_TARGET_REFUSED: {name} on {:#x}", w.to)))
+        }
+    }
+
+    async fn require_bound(&self, chain: &Chain, to: Address) -> Result<(), Refusal> {
+        if self.bound(chain, to).await? {
+            Ok(())
+        } else {
+            Err(Refusal::Policy(format!("CHAIN_UID_MISMATCH: {to:#x} is not bound to this chain (NODE-GW-07)")))
+        }
+    }
+
+    /// `chainUid()` of `to` equals this chain's; a contract without one is not bound.
+    async fn bound(&self, chain: &Chain, to: Address) -> Result<bool, Refusal> {
+        if self.bound.lock().is_ok_and(|b| b.contains(&to)) {
+            return Ok(true);
+        }
+        let uid = chain.uid().await.map_err(|e| Refusal::Transport(format!("chain_uid: {e:#}")))?;
+        let ok = match chain.call_view(to, IToken::chainUidCall {}).await {
+            Ok(u) => u == uid,
+            Err(SimError::Revert(_)) => false,
+            Err(SimError::Transport(e)) => return Err(Refusal::Transport(format!("chainUid(): {e}"))),
+        };
+        if ok {
+            if let Ok(mut b) = self.bound.lock() {
+                b.insert(to);
+            }
+        }
+        Ok(ok)
+    }
+
+    async fn table(&self, chain: &Chain, to: Address) -> Result<Arc<Table>, Refusal> {
+        if let Some(t) = self.tables.lock().ok().and_then(|t| t.get(&to).cloned()) {
+            return Ok(t);
+        }
+        let read = |e: SimError| match e {
+            SimError::Revert(r) => Refusal::Policy(format!("SELECTOR_NOT_ALLOWED: no published allowlist: {r}")),
+            SimError::Transport(r) => Refusal::Transport(format!("mtxSelectors(): {r}")),
+        };
+        let s = chain.call_view(to, IToken::mtxSelectorsCall {}).await.map_err(read)?;
+        let supported = chain.call_view(to, IToken::supportedModesCall {}).await.map_err(read)?;
+        let rows = s.selectors.iter().zip(&s.feeClass).zip(&s.amountArg).map(|((sel, c), a)| (sel.0, *c, *a)).collect();
+        let t = Arc::new(Table { rows, supported });
+        if let Ok(mut m) = self.tables.lock() {
+            m.insert(to, t.clone());
+        }
+        Ok(t)
+    }
+}
+
+/// Simulated gas → the gas limit, for the EVM submitter and the lane runner alike: `max` bounds the estimate;
+/// `mtxSettle` is sized until every planned settlement settles; a contract signer's meta-tx gets at least the
+/// ERC-1271 floor.
+pub async fn gas(chain: &Chain, w: &Work, max: u64) -> Result<u64, SimError> {
+    let est = chain.simulate(w.to, w.data.clone()).await?;
+    if est > max {
+        return Err(SimError::Revert(format!("gas {est} above max_gas_per_tx")));
+    }
+    if !w.entry && w.meta.is_none() && w.data.get(..4) == Some(&SEL_MTX_SETTLE[..]) {
+        return settle_gas(chain, w.to, &w.data, est, max).await;
+    }
+    let contract_signer = match &w.meta {
+        Some(m) => chain.has_code(m.from).await.map_err(|e| SimError::Transport(format!("eth_getCode: {e:#}")))?,
+        None => false,
+    };
+    Ok(gas_limit(est, contract_signer))
+}
+
+/// Size `mtxSettle` gas by simulation (P2b-2, NODE-DEX-15): from the estimate +20 %, raise ×1.5 until every planned
+/// settlement settles, never past `max`. A whole-call revert is the job's answer as it is (never retried with more gas:
+/// `SigCheckGasStarved` is forgeable by a hook-token destination).
+pub async fn settle_gas(chain: &Chain, to: Address, data: &Bytes, estimate: u64, max: u64) -> Result<u64, SimError> {
+    let mut g = gas_limit(estimate, false).min(max);
+    loop {
+        if settled_all(&chain.call_with_gas(to, data.clone(), g).await?) {
+            return Ok(g);
+        }
+        g = next_gas(g, max).ok_or_else(|| SimError::Revert(format!("mtxSettle does not settle every settlement within {max} gas")))?;
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use alloy::sol_types::{SolCall, SolError};
+
+    /// Every row's selector is the `cast sig` of its Solidity signature, and the KAT calldata starts with it.
+    #[test]
+    fn the_call_table_is_pinned() {
+        let kat = |f: &str, k: &str| -> Vec<u8> {
+            let p = format!("{}/../smartcontracts/evm/test/vectors/{f}", env!("CARGO_MANIFEST_DIR"));
+            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
+            alloy::hex::decode(&v[k].as_str().unwrap()[2..]).unwrap()
+        };
+        assert_eq!(kat("dex_order_kat.json", "settle_calldata")[..4], SEL_MTX_SETTLE);
+        assert_eq!(kat("dex_order_kat.json", "cancel_orders_calldata")[..4], CALL_TABLE[8].0);
+        assert_eq!(kat("dex_order_kat.json", "invalidate_calldata")[..4], SEL_MTX_INVALIDATE_NONCES);
+        assert_eq!(kat("trade_kat.json", "cancel_calldata")[..4], SEL_MTX_CANCEL_ORDER);
+        assert_eq!(crate::abi::ISCaaSDex::mtxSettleCall::SELECTOR, SEL_MTX_SETTLE);
+        assert_eq!(IToken::mtxWrapCall::SELECTOR, SEL_MTX_WRAP);
+        let sig = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
+        assert_eq!(CALL_TABLE[0].0, sig("deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)"));
+        assert_eq!(CALL_TABLE[1].0, sig("mtxExecuteAsOwner(bytes,uint256,uint256,bytes)"));
+        assert_eq!(CALL_TABLE[2].0, sig("mtxExecuteAsOwnerRaw(bytes,uint256,uint256,bytes)"));
+        assert_eq!(CALL_TABLE[3].0, sig("mtxPayUnderMandate(address,address,uint256,bytes32,uint64,uint256,bytes)"));
+        assert_eq!(CALL_TABLE[4].0, sig("mtxRevoke(address,uint64,uint256,bytes)"));
+        let order = "(address,address,uint256,uint256,uint256,uint256,address,address,address,uint8,uint256,uint256,uint256)";
+        let plan = format!("(bytes32,(address,{order},bytes,uint256,uint256)[],address[])");
+        assert_eq!(CALL_TABLE[6].0, sig(&format!("mtxExchange({plan},(address,bytes)[])")));
+        assert_eq!(CALL_TABLE[7].0, sig(&format!("mtxExchangeVia({plan},address,bytes)")));
+        // no token transfer, approval or meta-tx entry is a row: those reach a token only as `metatx` jobs
+        for s in ["transfer(address,uint256)", "approve(address,uint256)", "transferFrom(address,address,uint256)"] {
+            assert!(row(sig(s)).is_none(), "{s}");
+        }
+        assert!(row(IToken::mtxExecuteCall::SELECTOR).is_none() && row(IToken::mtxExecuteTransferCall::SELECTOR).is_none());
+        assert!(row(SEL_MTX_CANCEL_ORDER).is_none() && row(SEL_MTX_WRAP).is_none());
+        // and each row keeps its rule
+        let rules: Vec<Rule> = CALL_TABLE.iter().map(|r| r.2).collect();
+        assert_eq!(rules, [Rule::AccountFactory, Rule::SelfAuth, Rule::SelfAuth, Rule::SelfAuth, Rule::SelfAuth,
+            Rule::Dex, Rule::Dex, Rule::Dex, Rule::Dex, Rule::Dex]);
+    }
+
+    /// An entry job carries only an order or wrap entry; anything else is refused before any chain read.
+    #[tokio::test]
+    async fn an_entry_job_is_only_an_entry() {
+        let cfg = ChainCfg { evm_chain_number: 7, rpc_urls: vec!["http://127.0.0.1:9".into()], ..Default::default() };
+        let chain = Chain::with_signer(&cfg, alloy::signers::local::PrivateKeySigner::random()).unwrap();
+        let g = Guard::new(&cfg, Default::default());
+        let w = |data: Vec<u8>| Work { job_id: Some(1), to: Address::repeat_byte(1), data: data.into(), valid_until: 0, meta: None, entry: true };
+        let transfer = IToken::transferCall { to: Address::repeat_byte(2), value: alloy::primitives::U256::from(1) }.abi_encode();
+        assert!(matches!(g.check(&chain, &w(transfer)).await, Err(Refusal::Policy(r)) if r.starts_with("CALL_TARGET_REFUSED")));
+        assert!(matches!(g.check(&chain, &w(vec![])).await, Err(Refusal::Policy(_))));
+        // an entry passes the selector check and then needs the chain (unreachable here: transient, never dead)
+        let cancel = [&SEL_MTX_CANCEL_ORDER[..], &[0u8; 32]].concat();
+        assert!(matches!(g.check(&chain, &w(cancel)).await, Err(Refusal::Transport(_))));
+    }
+
+    #[test]
+    fn each_rule_needs_its_target() {
+        let bound = Facts { bound: true, ..Default::default() };
+        assert!(allowed(Rule::SelfAuth, &bound));
+        assert!(!allowed(Rule::SelfAuth, &Facts { bound: false, ..bound }), "NODE-GW-07");
+        assert!(!allowed(Rule::SelfAuth, &Facts { token: true, ..bound }), "never a registered token");
+        assert!(!allowed(Rule::SelfAuth, &Facts { token_factory: true, ..bound }), "never the token factory");
+        assert!(!allowed(Rule::Dex, &bound), "only a listed DEX");
+        assert!(allowed(Rule::Dex, &Facts { dex: true, ..bound }));
+        assert!(!allowed(Rule::Dex, &Facts { dex: true, token: true, ..bound }));
+        assert!(!allowed(Rule::Dex, &Facts { dex: true, bound: false, ..bound }));
+        assert!(!allowed(Rule::AccountFactory, &bound), "only the account factory");
+        assert!(allowed(Rule::AccountFactory, &Facts { account_factory: true, ..bound }));
+        assert!(!allowed(Rule::AccountFactory, &Facts { account_factory: true, bound: false, ..bound }));
+    }
+
+    #[test]
+    fn self_calls_follow_the_published_allowlist() {
+        let t = Table { rows: vec![([1, 2, 3, 4], 1, 0), ([5, 6, 7, 8], 2, 1)], supported: 0xF3 };
+        let data = |sel: [u8; 4], words: usize| [&sel[..], &vec![0u8; 32 * words]].concat();
+        self_call_ok(&t, &data([1, 2, 3, 4], 1), 0x21).unwrap();
+        assert!(self_call_ok(&t, &data([9, 9, 9, 9], 1), 0).is_err(), "not allowlisted");
+        assert!(self_call_ok(&t, &[1, 2, 3], 0).is_err(), "short");
+        assert!(self_call_ok(&t, &data([1, 2, 3, 4], 1), 0x10).is_err(), "PERCENT on ABSOLUTE");
+        self_call_ok(&t, &data([1, 2, 3, 4], 1), 0x20).unwrap();
+        self_call_ok(&t, &data([5, 6, 7, 8], 2), 0x10).unwrap();
+        assert!(self_call_ok(&t, &data([5, 6, 7, 8], 1), 0x10).is_err(), "AMOUNT basis argument missing");
+        let narrow = Table { supported: 0x03, ..t.clone() };
+        assert!(self_call_ok(&narrow, &data([1, 2, 3, 4], 1), 0x20).is_err(), "fee bits outside supportedModes");
+        self_call_ok(&narrow, &data([1, 2, 3, 4], 1), 0x03).unwrap();
+        let odd = Table { rows: vec![([1, 2, 3, 4], 3, 0)], supported: 0xF3 };
+        assert!(self_call_ok(&odd, &data([1, 2, 3, 4], 1), 0).is_err(), "unknown fee class");
+    }
+
+    #[test]
+    fn gas_floor_and_settle_sizing() {
+        assert_eq!(ERC1271_FLOOR, 432_349);
+        assert_eq!(gas_limit(100_000, false), 120_000);
+        assert_eq!(gas_limit(100_000, true), ERC1271_FLOOR);
+        assert_eq!(gas_limit(1_000_000, true), 1_200_000);
+        assert_eq!(next_gas(1_000, 3_000), Some(1_500));
+        assert_eq!(next_gas(2_500, 3_000), Some(3_000));
+        assert_eq!(next_gas(3_000, 3_000), None);
+        let ok = |v: Vec<bool>| <Vec<bool> as SolValue>::abi_encode(&v);
+        assert!(settled_all(&ok(vec![true, true])));
+        assert!(!settled_all(&ok(vec![true, false])), "an empty MatchFailed is out of gas: more gas, never invalid");
+        assert!(!settled_all(&ok(vec![])));
+        assert!(!settled_all(&[1, 2, 3]));
+    }
+
+    #[test]
+    fn an_invalidation_already_done_is_success() {
+        let reason = crate::abi::decode_revert(
+            &IToken::MinNonceNotIncreasing { current: alloy::primitives::U256::from(9), requested: alloy::primitives::U256::from(5) }.abi_encode());
+        let inv = [&SEL_MTX_INVALIDATE_NONCES[..], &[0u8; 128]].concat();
+        assert!(already_invalidated(&inv, &reason));
+        assert!(!already_invalidated(&[&SEL_MTX_CANCEL_ORDER[..], &[0u8; 128]].concat(), &reason));
+        assert!(!already_invalidated(&inv, "MinNonceAboveCap(MinNonceAboveCap { requested: 1 })"));
+    }
+}
diff --git a/scaas-node/src/lib.rs b/scaas-node/src/lib.rs
index b31b39a..9e5391f 100644
--- a/scaas-node/src/lib.rs
+++ b/scaas-node/src/lib.rs
@@ -11,6 +11,7 @@ pub mod dex;
 pub mod drift;
 pub mod finality;
 pub mod gateway;
+pub mod guard;
 pub mod gwauth;
 pub mod indexer;
 pub mod keys;
diff --git a/scaas-node/src/submit.rs b/scaas-node/src/submit.rs
index 2abb758..07d1a24 100644
--- a/scaas-node/src/submit.rs
+++ b/scaas-node/src/submit.rs
@@ -19,6 +19,7 @@ use crate::breaker::Breaker;
 use crate::chain::{Chain, SimError};
 use crate::abi::IToken;
 use crate::config::ChainCfg;
+use crate::guard::{self, Guard, Refusal};
 use crate::metatx::{addr, uint, Mtx};
 use crate::nonce::{bump, plan, Inflight};
 use crate::odoo::{Job, Odoo, Report};
@@ -42,6 +43,8 @@ pub struct Work {
     pub valid_until: u64,
     /// `None` cho job `call`.
     pub meta: Option<MetaRef>,
+    /// A token's order or wrap entry (`metatx` job naming `entry`), not a `call` (`guard`).
+    pub entry: bool,
 }
 
 /// Meta-tx bên trong `Work`: đủ để đọc nonce chủ thể (R80) và nhận ra digest trong event (§8.5).
@@ -112,7 +115,7 @@ pub fn work_from_job(job: &Job) -> Result<Work> {
     if let Some(c) = &job.call {
         let data = alloy::hex::decode(c.calldata.strip_prefix("0x").unwrap_or(&c.calldata))?;
         let valid_until = c.valid_until.parse::<u64>()?;
-        return Ok(Work { job_id: Some(job.id), to: c.target, data: data.into(), valid_until, meta: None });
+        return Ok(Work { job_id: Some(job.id), to: c.target, data: data.into(), valid_until, meta: None, entry: false });
     }
     let (Some(m), Some(token), Some(sig)) = (&job.metatx, job.token, &job.signature) else {
         anyhow::bail!("job {} has neither a meta-transaction nor a call", job.id);
@@ -121,7 +124,7 @@ pub fn work_from_job(job: &Job) -> Result<Work> {
     let sig = alloy::hex::decode(sig.strip_prefix("0x").unwrap_or(sig))?;
     let valid_until = m.valid_until().saturating_to();
     let meta = Some(MetaRef::of(token, &m, job_digest(job)));
-    Ok(Work { job_id: Some(job.id), to: token, data: m.calldata(sig.into()), valid_until, meta })
+    Ok(Work { job_id: Some(job.id), to: token, data: m.calldata(sig.into()), valid_until, meta, entry: false })
 }
 
 /// A token's other signed entry point as a `metatx` job (job-api.md, order and wrap entries): the signature is in the
@@ -155,7 +158,7 @@ fn entry_work(job: &Job, entry: &str) -> Result<Work> {
         }
         e => anyhow::bail!("unknown entry {e:?}"),
     };
-    Ok(Work { job_id: Some(job.id), to: token, data: data.into(), valid_until, meta: None })
+    Ok(Work { job_id: Some(job.id), to: token, data: data.into(), valid_until, meta: None, entry: true })
 }
 
 pub fn now() -> u64 {
@@ -175,6 +178,8 @@ pub struct Submitter {
     breaker: Arc<Mutex<Breaker>>,
     sampled: Option<Instant>,
     tripped: Option<&'static str>,
+    /// PAY-FIX2, NODE-GW-07, NODE-JOB-20: checked before every simulation.
+    guard: Guard,
 }
 
 impl Submitter {
@@ -184,6 +189,8 @@ impl Submitter {
         let nc = odoo
             .node_config_ref(serde_json::json!(cfg.evm_chain_number), Some(format!("{:#x}", chain.address())), Some(node_id.clone()))
             .await?;
+        // NODE-GW-07: a lane of a chain whose block 0 is not the configured chain_uid never starts.
+        let uid = chain.uid().await?;
         let pending = chain.pending_nonce().await?;
         let jobs: Vec<Inflight> = nc
             .inflight
@@ -192,6 +199,8 @@ impl Submitter {
             .collect();
         let p = plan(pending, nc.journal_max_nonce, &jobs);
         let breaker = Arc::new(Mutex::new(Breaker::new(cfg.breaker.clone())));
+        let tokens = std::sync::RwLock::new(nc.tokens.iter().filter_map(crate::odoo::TokenCfg::evm).collect());
+        let guard = Guard::new(&cfg, Arc::new(tokens));
         let mut me = Self {
             chain,
             odoo,
@@ -204,6 +213,7 @@ impl Submitter {
             breaker,
             sampled: None,
             tripped: None,
+            guard,
         };
         for n in &p.gap_fill {
             me.gap_fill(*n).await?;
@@ -221,7 +231,7 @@ impl Submitter {
             let gas = me.cfg.max_gas_per_tx;
             me.inflight.insert(n, Sent { work, hashes: vec![hash], gas, fees, at: Instant::now(), _guard: guard });
         }
-        info!(chain = me.cfg.evm_chain_number, next = me.next, tracked = me.inflight.len(), "submit ready");
+        info!(chain = me.cfg.evm_chain_number, chain_uid = %uid, next = me.next, tracked = me.inflight.len(), "submit ready");
         Ok(me)
     }
 
@@ -327,9 +337,13 @@ impl Submitter {
             }
             return;
         }
-        let gas = match self.chain.simulate(w.to, w.data.clone()).await {
-            Ok(g) if g <= self.cfg.max_gas_per_tx => g + g / 5,
-            Ok(g) => return self.fail(&w, format!("gas {g} above max_gas_per_tx")).await,
+        match self.guard.check(&self.chain, &w).await {
+            Ok(()) => {}
+            Err(Refusal::Policy(reason)) => return self.fail(&w, reason).await,
+            Err(Refusal::Transport(reason)) => return self.requeue(&w, reason).await,
+        }
+        let gas = match guard::gas(&self.chain, &w, self.cfg.max_gas_per_tx).await {
+            Ok(g) => g,
             Err(SimError::Revert(reason)) => return self.refused(&w, reason).await,
             Err(SimError::Transport(reason)) => return self.requeue(&w, format!("simulate: {reason}")).await,
         };
@@ -364,8 +378,14 @@ impl Submitter {
     }
 
     /// Mô phỏng revert. Meta-tx mà nonce chủ thể đã qua ⇒ `consumed` (R80: relayer khác có thể đã đưa nó lên chain),
-    /// không `dead`; không đọc được nonce ⇒ tạm thời.
+    /// không `dead`; không đọc được nonce ⇒ tạm thời. An invalidation already in force is done, never dead (MT-8).
     async fn refused(&self, w: &Work, reason: String) {
+        if guard::already_invalidated(&w.data, &reason) {
+            if let Some(id) = w.job_id {
+                self.report(id, "consumed", None, None, Some("already_invalidated".into())).await;
+            }
+            return;
+        }
         match self.consumed(w).await {
             Ok(true) => self.report_consumed(w).await,
             Ok(false) => self.fail(w, reason).await,
@@ -639,6 +659,8 @@ mod tests {
     use crate::adapter::tests::{fake_odoo, Fake, Shared};
 
     const D: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";
+    /// The fake chain's `chain_uid`: pinned in the config (the fake serves no block 0) and answered by `chainUid()`.
+    const UID: u64 = 0x24;
     const TOKEN: Address = Address::repeat_byte(0xcd);
 
     /// Chain EVM giả qua JSON-RPC thật (alloy nói chuyện với nó như với node thật).
@@ -653,6 +675,14 @@ mod tests {
         receipts: HashMap<B256, bool>,
         /// (hash, to, input) mỗi lần `eth_sendRawTransaction`.
         sent: Vec<(B256, Address, Bytes)>,
+        /// The gas limit of each sent tx.
+        gas: Vec<u64>,
+        /// `chainUid()` answers this instead of `UID` (a contract of another chain).
+        uid: Option<u64>,
+        /// `eth_getCode` of every address is non-empty (a contract signer).
+        contract_signer: bool,
+        /// `mtxSettle` settles everything only from this much gas (below: one `ok` false, an empty `MatchFailed`).
+        settle_from: u64,
     }
     type Rpc = Arc<Mutex<Evm>>;
 
@@ -674,10 +704,28 @@ mod tests {
                     "gasUsedRatio": [0.5], "reward": [["0x3b9aca00"]]})),
                 "eth_blockNumber" => Ok(json!("0x10")),
                 "eth_getLogs" => Ok(json!([])),
+                "eth_getBlockByNumber" => Ok(Value::Null),
+                "eth_getCode" => Ok(json!(if e.contract_signer { "0x6001" } else { "0x" })),
                 "eth_call" => {
                     let input = p[0]["input"].as_str().or(p[0]["data"].as_str()).unwrap();
                     let sel = alloy::hex::decode(&input[2..10]).unwrap();
-                    if sel == IToken::mtxNonceCall::SELECTOR {
+                    if sel == IToken::mtxSelectorsCall::SELECTOR {
+                        // the published allowlist: cancelNonce, ABSOLUTE
+                        let out = IToken::mtxSelectorsCall::abi_encode_returns(&IToken::mtxSelectorsReturn {
+                            selectors: vec![alloy::primitives::FixedBytes::<4>::from([0xcf, 0xdd, 0x7a, 0xea])],
+                            feeClass: vec![1],
+                            amountArg: vec![0],
+                        });
+                        Ok(json!(format!("0x{}", alloy::hex::encode(out))))
+                    } else if sel == IToken::supportedModesCall::SELECTOR {
+                        Ok(word(U256::from(0xF3)))
+                    } else if sel == IToken::chainUidCall::SELECTOR {
+                        Ok(word(U256::from(e.uid.unwrap_or(UID))))
+                    } else if sel == guard::SEL_MTX_SETTLE {
+                        let gas = p[0]["gas"].as_str().map_or(u64::MAX, |g| u64::from_str_radix(&g[2..], 16).unwrap());
+                        let ok = vec![true, gas >= e.settle_from];
+                        Ok(json!(format!("0x{}", alloy::hex::encode(<Vec<bool> as SolValue>::abi_encode(&ok)))))
+                    } else if sel == IToken::mtxNonceCall::SELECTOR {
                         e.mtx_nonce.map(|n| word(U256::from(n))).ok_or_else(|| err(-32000, "upstream timeout", None))
                     } else {
                         match e.sim {
@@ -686,6 +734,11 @@ mod tests {
                                 let data = alloy::sol_types::SolError::abi_encode(&data);
                                 Err(err(3, "execution reverted", Some(format!("0x{}", alloy::hex::encode(data)))))
                             }
+                            Some("min_nonce") => {
+                                let data = IToken::MinNonceNotIncreasing { current: U256::from(9), requested: U256::from(9) };
+                                let data = alloy::sol_types::SolError::abi_encode(&data);
+                                Err(err(3, "execution reverted", Some(format!("0x{}", alloy::hex::encode(data)))))
+                            }
                             Some(_) => Err(err(-32000, "upstream timeout", None)),
                             None => Ok(word(U256::from(1))),
                         }
@@ -696,6 +749,7 @@ mod tests {
                     let tx = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
                     let h = *tx.tx_hash();
                     e.sent.push((h, tx.to().unwrap(), tx.input().clone()));
+                    e.gas.push(tx.gas_limit());
                     Ok(json!(format!("{h:#x}")))
                 }
                 "eth_getTransactionReceipt" => {
@@ -748,6 +802,10 @@ mod tests {
     }
 
     async fn lane(rpc: &str, odoo: crate::odoo::Odoo, key: u8, set: InflightSet) -> Submitter {
+        lane_with(rpc, odoo, key, set, None).await
+    }
+
+    async fn lane_with(rpc: &str, odoo: crate::odoo::Odoo, key: u8, set: InflightSet, dex: Option<Address>) -> Submitter {
         let cfg = ChainCfg {
             family: "evm".into(),
             evm_chain_number: 31337,
@@ -755,6 +813,8 @@ mod tests {
             stuck_after_secs: 0,
             max_gas_per_tx: 3_000_000,
             max_fee_cap_gwei: 500,
+            chain_uid: Some(B256::from(U256::from(UID))),
+            dex,
             ..Default::default()
         };
         let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(key)).unwrap();
@@ -851,6 +911,73 @@ mod tests {
         }
     }
 
+    /// PAY-FIX2 / NODE-GW-07 / MT-8, wired into the submitter: refusals come before any simulation or signature.
+    #[tokio::test]
+    async fn the_guard_runs_before_simulation_and_signing() {
+        let run = |e: Evm, jobs: Vec<Value>, dex: Option<Address>| async move {
+            let (url, rpc) = fake_evm(e).await;
+            let (odoo, o) = fake_odoo(Fake { jobs, tokens: json!([{"address": format!("{TOKEN:#x}"), "decimals": 6}]), ..Default::default() }).await;
+            lane_with(&url, odoo, 1, InflightSet::default(), dex).await.poll_outbox().await;
+            let last = o.lock().unwrap().reports.last().cloned().unwrap();
+            let sent = rpc.lock().unwrap().sent.len();
+            (last["chain_state"].as_str().unwrap().to_string(), last["error"].as_str().unwrap_or_default().to_string(), sent, rpc)
+        };
+        let call = |target: Address, data: Vec<u8>| json!({"id": 9, "kind": "call", "call": {"target": format!("{target:#x}"),
+            "calldata": format!("0x{}", alloy::hex::encode(data)), "validUntil": (now() + 300).to_string()}});
+        // a lane's own token balance never leaves through a `call` job
+        let steal = IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1) }.abi_encode();
+        let (st, err, sent, _) = run(Evm { mtx_nonce: Some(0), ..Default::default() }, vec![call(TOKEN, steal)], None).await;
+        assert_eq!((st.as_str(), sent), ("dead", 0));
+        assert!(err.starts_with("CALL_TARGET_REFUSED"), "{err}");
+        // a call-table row on a target it does not name: `mtxSettle` on a registered token
+        let settle = [&guard::SEL_MTX_SETTLE[..], &[0u8; 32]].concat();
+        let (st, err, ..) = run(Evm::default(), vec![call(TOKEN, settle.clone())], Some(TOKEN)).await;
+        assert_eq!(st, "dead");
+        assert!(err.starts_with("CALL_TARGET_REFUSED"), "{err}");
+        // a meta-transaction on a contract of another chain
+        let (st, err, sent, _) = run(Evm { uid: Some(0x25), mtx_nonce: Some(0), ..Default::default() }, vec![job(7)], None).await;
+        assert_eq!((st.as_str(), sent), ("dead", 0));
+        assert!(err.starts_with("CHAIN_UID_MISMATCH"), "{err}");
+        // an order entry on a contract of another chain
+        let inv_on = |token: Address| json!({"id": 8, "kind": "metatx", "entry": "mtxInvalidateNonces", "token": format!("{token:#x}"),
+            "from": format!("{:#x}", Address::repeat_byte(0xab)), "batch": "1", "newMin": "9",
+            "signature": format!("0x{}", "11".repeat(65)), "validUntil": (now() + 300).to_string()});
+        let (st, err, sent, _) = run(Evm { uid: Some(0x25), ..Default::default() }, vec![inv_on(TOKEN)], None).await;
+        assert_eq!((st.as_str(), sent), ("dead", 0));
+        assert!(err.starts_with("CHAIN_UID_MISMATCH"), "{err}");
+        // a self-call outside the token's published allowlist (NODE-JOB-20); on it, it goes
+        let self_call = |data: &str| {
+            let m = Mtx::Call(crate::abi::MetaTransaction { from: Address::repeat_byte(0xab), data: alloy::hex::decode(data).unwrap().into(),
+                batch: U256::from(7), nonce: U256::ZERO, validUntil: U256::from(now() + 600), mode: 0, relayer: Address::ZERO,
+                fee: U256::ZERO, feeRecipient: Address::ZERO });
+            let (kind, wire) = m.to_wire();
+            json!({"id": 7, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
+                   "signature": format!("0x{}", "11".repeat(65)), "metatx": wire})
+        };
+        let (st, err, sent, _) = run(Evm { mtx_nonce: Some(0), ..Default::default() }, vec![self_call("12345678")], None).await;
+        assert_eq!((st.as_str(), sent), ("dead", 0));
+        assert!(err.starts_with("SELECTOR_NOT_ALLOWED"), "{err}");
+        let cancel = format!("cfdd7aea{}", "00".repeat(32));
+        let (st, err, sent, _) = run(Evm { mtx_nonce: Some(0), ..Default::default() }, vec![self_call(&cancel)], None).await;
+        assert_eq!((st.as_str(), sent), ("broadcast", 1), "{err}");
+        // an invalidation already in force is done, never dead
+        let inv = json!({"id": 8, "kind": "metatx", "entry": "mtxInvalidateNonces", "token": format!("{TOKEN:#x}"),
+            "from": format!("{:#x}", Address::repeat_byte(0xab)), "batch": "1", "newMin": "9",
+            "signature": format!("0x{}", "11".repeat(65)), "validUntil": (now() + 300).to_string()});
+        let (st, err, sent, _) = run(Evm { sim: Some("min_nonce"), ..Default::default() }, vec![inv], None).await;
+        assert_eq!((st.as_str(), err.as_str(), sent), ("consumed", "already_invalidated", 0));
+        // mtxSettle on the chain's DEX: gas raised until every settlement settles (an empty MatchFailed is gas)
+        let dex = Address::repeat_byte(0xd0);
+        let (st, _, sent, rpc) = run(Evm { settle_from: 300_000, ..Default::default() }, vec![call(dex, settle)], Some(dex)).await;
+        assert_eq!((st.as_str(), sent), ("broadcast", 1));
+        let g = rpc.lock().unwrap().gas[0];
+        assert!(g >= 300_000 && g == 0x30000 * 6 / 5 * 3 / 2, "estimate +20 %, then ×1.5 once: {g}");
+        // a contract signer's meta-tx gets the ERC-1271 floor
+        let (st, _, _, rpc) = run(Evm { mtx_nonce: Some(0), contract_signer: true, ..Default::default() }, vec![job(7)], None).await;
+        assert_eq!(st, "broadcast");
+        assert_eq!(rpc.lock().unwrap().gas[0], guard::ERC1271_FLOOR);
+    }
+
     /// The token's order entries as `metatx` jobs (job-api.md): byte-identical with the forge KAT's relayed calldata.
     #[test]
     fn entry_jobs_encode_as_the_token_reads_them() {
diff --git a/scaas-node/tests/e2e.rs b/scaas-node/tests/e2e.rs
index 8d5f717..e26de58 100644
--- a/scaas-node/tests/e2e.rs
+++ b/scaas-node/tests/e2e.rs
@@ -350,7 +350,7 @@ async fn outbox_payment_reaches_chain_and_comes_back_final() {
     assert_eq!(reports[0]["outer_nonce"], 0);
     assert_eq!(balance(&rpc, token, shop).await, U256::from(250_000_000u64));
 
-    let ichain = Chain::with_signer(&cfg, relayer).unwrap();
+    let ichain = Chain::with_signer(&cfg, relayer.clone()).unwrap();
     assert!(scaas_node::indexer::step(&ichain, &odoo).await.unwrap());
     let ingested = state.lock().unwrap().ingested.clone();
     let pay = ingested.iter().find(|e| e["event"] == "PaymentSettled").expect("PaymentSettled ingested");
@@ -383,6 +383,50 @@ async fn outbox_payment_reaches_chain_and_comes_back_final() {
     s.poll_outbox().await;
     let last = state.lock().unwrap().reports.last().cloned().unwrap();
     assert_eq!((last["job_id"].as_i64(), last["chain_state"].as_str(), last["error"].as_str()), (Some(2), Some("consumed"), Some("landed")), "{last}");
+
+    // PAY-FIX2 on a real chain: the lane holds fee income in the token, and a `call` job that would move it is refused
+    // before simulation; a meta-transaction to a contract not bound to this chain (here: no contract) too (NODE-GW-07).
+    let steal = IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1u64) }.abi_encode();
+    let mut jobs = vec![json!({"id": 3, "kind": "call", "call": {"target": format!("{token:#x}"),
+        "calldata": format!("0x{}", alloy::hex::encode(steal)), "validUntil": (now() + 300).to_string()}})];
+    let elsewhere = Address::repeat_byte(0x99);
+    jobs.push(job(4, elsewhere, &m, "0x", sign(&payer, &token_domain(&dep, chain_id, elsewhere), &m)));
+    state.lock().unwrap().jobs.extend(jobs);
+    let nonce = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_transaction_count(relayer.address()).await.unwrap();
+    s.poll_outbox().await;
+    let reports = state.lock().unwrap().reports.clone();
+    let of = |id: i64| reports.iter().rev().find(|r| r["job_id"] == id).unwrap().clone();
+    assert_eq!(of(3)["chain_state"], "dead");
+    assert!(of(3)["error"].as_str().unwrap().starts_with("CALL_TARGET_REFUSED"), "{}", of(3));
+    assert_eq!(of(4)["chain_state"], "dead");
+    assert!(of(4)["error"].as_str().unwrap().starts_with("CHAIN_UID_MISMATCH"), "{}", of(4));
+    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
+    assert_eq!(p.get_transaction_count(relayer.address()).await.unwrap(), nonce, "nothing signed or sent");
+
+    // NODE-JOB-20 against the real token: a `call` struct runs only a selector of its published allowlist. A self-call
+    // of `transfer` is refused before simulation; `cancelNonce(99)` lands and moves the payer's lane 99.
+    let call = |data: Vec<u8>, batch: u64| Mtx::Call(scaas_node::abi::MetaTransaction { from: payer.address(), data: data.into(),
+        batch: U256::from(batch), nonce: U256::ZERO, validUntil: U256::from(now() + 300), mode: 0, relayer: Address::ZERO,
+        fee: U256::ZERO, feeRecipient: Address::ZERO });
+    let bad = call(IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1u64) }.abi_encode(), 5);
+    let good = call(alloy::hex::decode(format!("cfdd7aea{:064x}", 99)).unwrap(), 6);
+    state.lock().unwrap().jobs.extend([job(5, token, &bad, "0x", sign(&payer, &d, &bad)), job(6, token, &good, "0x", sign(&payer, &d, &good))]);
+    s.poll_outbox().await;
+    for _ in 0..50 {
+        s.track().await;
+        if s.inflight_count() == 0 {
+            break;
+        }
+        tokio::time::sleep(Duration::from_millis(100)).await;
+    }
+    let reports = state.lock().unwrap().reports.clone();
+    let of = |id: i64| reports.iter().rev().find(|r| r["job_id"] == id).unwrap().clone();
+    assert_eq!(of(5)["chain_state"], "dead");
+    assert!(of(5)["error"].as_str().unwrap().starts_with("SELECTOR_NOT_ALLOWED"), "{}", of(5));
+    assert_eq!(of(6)["chain_state"], "mined", "{}", of(6));
+    let lane99 = IToken::mtxNonceCall { from: payer.address(), batch: U256::from(99) }.abi_encode();
+    let out = p.call(TransactionRequest::default().to(token).input(lane99.into())).await.unwrap();
+    assert_eq!(U256::abi_decode(&out).unwrap(), U256::from(1u64));
 }
 
 fn sign_hash(signer: &PrivateKeySigner, h: B256) -> String {
``````


### Task 5: clientkeys on `MetaTransfer` payments, the self-call allowlist, trade orders and cancels

`checkPayment` leaves the v1 `MetaTransaction{to, value, data = pay(...)}` (L15) for the salted `MetaTransfer`: the
token, `chainUid`, `entryRef`, amount, payee, fee bounds, validity, `expectedToken` (CLI-SGN-08). `checkCall` checks a
self-call against the contract's allowlist (no `transfer`/`approve`/`mtx…` through `call`). `tradeOrderTypedData`
builds a `TradeOrder` in the sell token's domain or a `DexOrder` in the DEX's; `orderCancelTypedData` a `CancelOrder`
or `InvalidateNonces`; `checkTradeOrder` refuses an unlisted `dex`, a `receiveToken` that is not a listed wrapper for a
wrap, and the EOA `approve` path (CLI-SGN-05, -33…-36). The EIP-712 encoder handles nested structs (`DexOrder`). The
KAT tests read `metatransfer_kat.json`, `trade_kat.json`, `dex_order_kat.json`.

**Files:** modify `clients/clientkeys/src/{evm,passkey-signer,seed-signer}.js`, `clients/clientkeys/test/evm.test.js`.

- [ ] **Step 1: Apply the diff below.**
- [ ] **Step 2: Gate.** `cd clients/clientkeys && ../../scripts/capped npm test` — 60 tests, 58 pass, 2 skipped (P4: 56, 54, 2).
- [ ] **Step 3: Commit** `P5 T5: clientkeys on MetaTransfer payments, self-call allowlist, trade orders (TradeOrder/DexOrder), cancels; v1 payment check gone`.

``````diff
diff --git a/clients/clientkeys/src/evm.js b/clients/clientkeys/src/evm.js
index f9c5654..2cee325 100644
--- a/clients/clientkeys/src/evm.js
+++ b/clients/clientkeys/src/evm.js
@@ -15,13 +15,21 @@ export function evmAddress(uncompressed) {
   return checksumAddress(hex(keccak_256(uncompressed.subarray(1)).subarray(12)));
 }
 
-// ------------------------------------------------------------------ EIP-712 (flat structs)
+// ------------------------------------------------------------------ EIP-712 (structs, nested structs)
 
+/** EIP-712 `encodeType`: the primary type, then every struct it references, sorted by name. */
 function encodeType(types, primary) {
-  return `${primary}(${types[primary].map((f) => `${f.type} ${f.name}`).join(',')})`;
+  const deps = new Set();
+  const walk = (t) => types[t].forEach((f) => {
+    if (types[f.type] && f.type !== primary && !deps.has(f.type)) { deps.add(f.type); walk(f.type); }
+  });
+  walk(primary);
+  const one = (t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(',')})`;
+  return [primary, ...[...deps].sort()].map(one).join('');
 }
 
-function encodeValue(type, value) {
+function encodeValue(type, value, types) {
+  if (types && types[type]) return hashStruct(types, type, value);
   if (type === 'string') return keccak_256(utf8ToBytes(String(value)));
   if (type === 'bytes') return keccak_256(value instanceof Uint8Array ? value : fromHex(value));
   if (type === 'address') return addressWord(value);
@@ -34,7 +42,7 @@ function encodeValue(type, value) {
 export function hashStruct(types, primary, data) {
   return keccak_256(concatBytes(
     keccak_256(utf8ToBytes(encodeType(types, primary))),
-    ...types[primary].map((f) => encodeValue(f.type, data[f.name])),
+    ...types[primary].map((f) => encodeValue(f.type, data[f.name], types)),
   ));
 }
 
@@ -128,11 +136,23 @@ const MTX_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, MetaTransaction: ['from:ad
   'nonce:uint256', 'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256', 'feeRecipient:address']
   .map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })) };
 const ZERO_ADDRESS = '0x' + '00'.repeat(20);
-const PAY_TYPES = { EIP712Domain: DOMAIN_TYPE, MetaTransaction: ['from:address', 'to:address', 'value:uint256',
-  'data:bytes', 'batch:uint256', 'nonce:uint256', 'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256',
-  'feeRecipient:address'].map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })) };
+const fields = (list) => list.map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] }));
+// The token's typed transfer and payment (CTR-MTX-23); `entryRef = 0` is a transfer, else a payment.
+const TRANSFER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, MetaTransfer: fields(['from:address', 'to:address',
+  'value:uint256', 'entryRef:bytes32', 'batch:uint256', 'nonce:uint256', 'validUntil:uint256', 'mode:uint32',
+  'relayer:address', 'fee:uint256', 'feeRecipient:address']) };
+// The role-free order (CTR-DEX-13), signed in the sell token's domain; an outside token's in the DEX's as `DexOrder`.
+const TRADE_ORDER = fields(['from:address', 'receiveToken:address', 'amount:uint256', 'receiveAmount:uint256',
+  'minFill:uint256', 'fee:uint256', 'relayer:address', 'dex:address', 'destination:address', 'flags:uint8',
+  'batch:uint256', 'nonce:uint256', 'validUntil:uint256']);
+const ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, TradeOrder: TRADE_ORDER };
+const DEX_ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, DexOrder: fields(['sellToken:address', 'order:TradeOrder']),
+  TradeOrder: TRADE_ORDER };
+const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
+// Never inside a `MetaTransaction` (CLI-SGN-34): moving funds is a `MetaTransfer`, and EOAs never approve (CLI-SGN-36).
+const NEVER_CALLED = new Set(['transfer(address,uint256)', 'transferFrom(address,address,uint256)',
+  'approve(address,uint256)', 'payWithFee(address,uint256,uint8,uint256,address,bytes32)', 'pay(bytes32)'].map(sel));
 export const ADD_KEY_SELECTOR = keccak_256(utf8ToBytes(`addKey(${KEY_TUPLE})`)).subarray(0, 4);
-const OP_PAY = keccak_256(utf8ToBytes('pay(bytes32)')).subarray(0, 4);
 const KEY_PROOF_PREFIX = utf8ToBytes('scaas-subject-key-proof-v1');
 
 const refuse = (why) => { throw new Error(`Refusing to sign: ${why}.`); };
@@ -208,25 +228,136 @@ function toBase(amount, decimals) {
   return BigInt(m[1] + (m[2] || '').padEnd(decimals, '0'));
 }
 
-/** The server's typed data must be a token `pay` of exactly the shown `amount` (in the token's
- *  `decimals`) from `account` on `chainId`, no fee, near deadline. Returns {digest, payee, token}. */
-export function checkPayment(td, { account, chainId, amount, decimals, now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
-  if (!td || td.primaryType !== 'MetaTransaction') refuse('this is not a payment');
+function salted({ name, contract, chainId, chainUid }) {
+  const salt = chainUid instanceof Uint8Array ? hex(chainUid) : String(chainUid);
+  if (!/^0x[0-9a-fA-F]{64}$/.test(salt)) refuse('the chain_uid is not 32 bytes');
+  return { name, version: '1', chainId: String(chainId), verifyingContract: contract, salt: salt.toLowerCase() };
+}
+
+/** A token's `MetaTransfer` (CTR-MTX-23) in its salted domain; unset fields 0; canonical zeroing as the contract hashes
+ *  it (`relayer` 0 unless mode bit 1, `feeRecipient` 0 unless mode bit 2). */
+export function metaTransferTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, message }) {
+  const m = { from: ZERO_ADDRESS, to: ZERO_ADDRESS, value: '0', entryRef: '0x' + '00'.repeat(32), batch: '0', nonce: '0',
+    validUntil: '0', mode: 0, relayer: ZERO_ADDRESS, fee: '0', feeRecipient: ZERO_ADDRESS, ...message };
+  const mode = BigInt(m.mode);
+  return {
+    types: TRANSFER_TYPES, primaryType: 'MetaTransfer', domain: salted({ name, contract, chainId, chainUid }),
+    message: { ...m, value: String(m.value), batch: String(m.batch), nonce: String(m.nonce), validUntil: String(m.validUntil),
+      fee: String(m.fee), relayer: mode & 1n ? m.relayer : ZERO_ADDRESS, feeRecipient: mode & 2n ? m.feeRecipient : ZERO_ADDRESS },
+  };
+}
+
+/** The server's typed data must be a token payment `MetaTransfer` of exactly the shown `amount` (in the token's
+ *  `decimals`) from `account`, in the token's domain salted with the signer's own `chainUid` (CLI-SGN-33), on the
+ *  signer's pinned `expectedToken` when given (CLI-SGN-08), with a non-zero reference (the request's, when `entryRef` is
+ *  given), no fee, a near deadline (CLI-SGN-05). Returns {digest, payee, token, entryRef}. */
+export function checkPayment(td, { account, chainId, chainUid, amount, decimals, entryRef, expectedToken,
+  now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
+  if (!td || td.primaryType !== 'MetaTransfer') refuse('this is not a payment');
   const m = td.message || {};
   const d = td.domain || {};
   if (uint(d.chainId, 'the chain') !== BigInt(chainId)) refuse('wrong network');
   if (!/^0x[0-9a-fA-F]{40}$/.test(String(d.verifyingContract)) || same(d.verifyingContract, account)) refuse('wrong token');
+  // CLI-SGN-08: the token from the signer's own profile, never from the server
+  if (expectedToken !== undefined && !same(d.verifyingContract, expectedToken)) refuse('wrong token');
   if (!same(m.from, account)) refuse('the payment is not from your account');
   if (uint(m.value, 'the amount') !== toBase(amount, decimals)) refuse('the amount differs from what you were shown');
-  let data;
-  try { data = fromHex(m.data); } catch { refuse('malformed data'); }
-  if (data.length !== 36 || hex(data.subarray(0, 4)) !== hex(OP_PAY)) refuse('this is not a plain payment');
+  if (!/^0x[0-9a-fA-F]{64}$/.test(String(m.entryRef)) || BigInt(m.entryRef) === 0n) refuse('this is not a payment');
+  if (entryRef !== undefined && !same(m.entryRef, entryRef)) refuse('the payment reference differs from the request');
   if (uint(m.fee, 'the fee') !== 0n) refuse('the payment carries a fee');
   if (![0, 1].includes(Number(m.mode))) refuse('unexpected payment mode');
   deadline(m.validUntil, now, maxWindow);
-  const mine = { types: PAY_TYPES, primaryType: 'MetaTransaction',
-    domain: { name: d.name, version: d.version, chainId: Number(chainId), verifyingContract: d.verifyingContract }, message: m };
+  const mine = metaTransferTypedData({ name: d.name, contract: d.verifyingContract, chainId, chainUid, message: m });
   const digest = digestOf(mine);
   if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected payment fields');
-  return { digest, payee: m.to, token: d.verifyingContract };
+  return { digest, payee: m.to, token: d.verifyingContract, entryRef: m.entryRef };
+}
+
+/** A self-call `MetaTransaction` (CTR-MTX-17) the user asked for: `data` decoded against the contract's published
+ *  allowlist `[{selector, name, feeClass}]` (`mtxSelectors()`, pinned per implementation version, CLI-SGN-34); an
+ *  unknown selector, a transfer/pay selector or an approval is refused; a PERCENT fee on an ABSOLUTE selector too.
+ *  Returns {digest, selector, name} for the review screen. */
+export function checkCall(td, { account, chainId, chainUid, allowlist, now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
+  if (!td || td.primaryType !== 'MetaTransaction') refuse('this is not a contract call');
+  const m = td.message || {};
+  const d = td.domain || {};
+  if (uint(d.chainId, 'the chain') !== BigInt(chainId)) refuse('wrong network');
+  if (!same(m.from, account)) refuse('the call is not from your account');
+  let data;
+  try { data = fromHex(m.data); } catch { refuse('malformed data'); }
+  if (data.length < 4) refuse('the call names no function');
+  const selector = hex(data.subarray(0, 4));
+  if (NEVER_CALLED.has(selector)) refuse('moving funds or an approval is never signed as a call');
+  const row = (allowlist || []).find((r) => same(r.selector, selector));
+  if (!row) refuse('the function is not on the contract\'s allowlist');
+  if (Number(row.feeClass) === 1 && (Number(m.mode) & 0xf0) === 0x10) refuse('a percentage fee on a fixed-fee call');
+  deadline(m.validUntil, now, maxWindow);
+  const mine = metaTxTypedData({ name: d.name, contract: d.verifyingContract, chainId, chainUid, message: m });
+  const digest = digestOf(mine);
+  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected call fields');
+  return { digest, selector, name: row.name };
+}
+
+/** A `TradeOrder` in its SCaaS sell token's salted domain (CTR-DEX-13), or for an outside sell token the `DexOrder`
+ *  `{sellToken, order}` in the DEX's (CTR-DEX-18): pass `dex` instead of `token`. */
+export function tradeOrderTypedData({ token, dex, sellToken, chainId, chainUid, order, name }) {
+  const o = { minFill: '0', fee: '0', relayer: ZERO_ADDRESS, destination: ZERO_ADDRESS, flags: 0, batch: '0', ...order };
+  const message = Object.fromEntries(TRADE_ORDER.map((f) => [f.name, f.type === 'address' || f.type === 'uint8' ? o[f.name] : String(o[f.name])]));
+  if (dex) {
+    return { types: DEX_ORDER_TYPES, primaryType: 'DexOrder', domain: salted({ name: name || 'SCaaS Dex', contract: dex, chainId, chainUid }),
+      message: { sellToken, order: message } };
+  }
+  return { types: ORDER_TYPES, primaryType: 'TradeOrder', domain: salted({ name: name || 'SCaaS MetaToken', contract: token, chainId, chainUid }),
+    message };
+}
+
+/** `CancelOrder(orderHash)` or `InvalidateNonces(from, batch, minNonce)` in the domain that holds the order (the sell
+ *  token, or the DEX for an outside token). */
+export function orderCancelTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, orderHash, invalidate }) {
+  const domain = salted({ name, contract, chainId, chainUid });
+  if (invalidate) {
+    return { types: { EIP712Domain: SALTED_DOMAIN_TYPE, InvalidateNonces: fields(['from:address', 'batch:uint256', 'minNonce:uint256']) },
+      primaryType: 'InvalidateNonces', domain,
+      message: { from: invalidate.from, batch: String(invalidate.batch), minNonce: String(invalidate.minNonce) } };
+  }
+  return { types: { EIP712Domain: SALTED_DOMAIN_TYPE, CancelOrder: fields(['orderHash:bytes32']) }, primaryType: 'CancelOrder',
+    domain, message: { orderHash } };
+}
+
+/** A trade order the user asked for (CLI-SGN-35): `dex` on the signer's pinned list of listed DEXes (or, for a wrap by
+ *  signature, CLI-SGN-36: `dex` = `receiveToken` = a pinned wrapper of that underlying and `minFill = amount`), `from`
+ *  the account, fee at most 1 %, known flags, a near deadline, the salt of the signer's chain. Returns {digest,
+ *  minFill (the effective one per settlement), warnings}. */
+export function checkTradeOrder(td, { account, chainId, chainUid, dexes = [], wrappers = [], now = Math.floor(Date.now() / 1000),
+  maxWindow = 30 * 86400 }) {
+  if (!td || !['TradeOrder', 'DexOrder'].includes(td.primaryType)) refuse('this is not a trade order');
+  const outside = td.primaryType === 'DexOrder';
+  const o = (outside ? (td.message || {}).order : td.message) || {};
+  const d = td.domain || {};
+  if (uint(d.chainId, 'the chain') !== BigInt(chainId)) refuse('wrong network');
+  if (!same(o.from, account)) refuse('the order is not from your account');
+  const wrap = wrappers.some((w) => same(w, o.dex));
+  if (wrap) {
+    if (outside || !same(o.receiveToken, o.dex) || uint(o.minFill, 'minFill') !== uint(o.amount, 'the amount')) {
+      refuse('a wrap by signature mints from this wrapper, all or nothing');
+    }
+  } else if (!dexes.some((x) => same(x, o.dex))) {
+    refuse('the order names a DEX that is not on your chain profile');
+  }
+  if (outside && !same(d.verifyingContract, o.dex)) refuse('an outside-token order is signed for its own DEX');
+  if (uint(o.fee, 'the fee') > 10000n) refuse('the fee is above 1 %');
+  if (BigInt(o.flags) & ~7n || (BigInt(o.flags) & 2n && !(BigInt(o.flags) & 1n))) refuse('unknown order flags');
+  const amount = uint(o.amount, 'the amount');
+  if (amount === 0n || uint(o.receiveAmount, 'the price') === 0n || uint(o.minFill, 'minFill') > amount) refuse('the amounts are malformed');
+  deadline(o.validUntil, now, maxWindow);
+  const mine = outside
+    ? tradeOrderTypedData({ dex: d.verifyingContract, name: d.name, sellToken: td.message.sellToken, chainId, chainUid, order: o })
+    : tradeOrderTypedData({ token: d.verifyingContract, name: d.name, chainId, chainUid, order: o });
+  const digest = digestOf(mine);
+  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected order fields');
+  const half = amount - amount / 2n;
+  const minFill = uint(o.minFill, 'minFill') > half ? uint(o.minFill, 'minFill') : half;
+  const warnings = same(o.destination, ZERO_ADDRESS) || same(o.destination, o.from) ? [] : ['someone else receives the proceeds'];
+  if (same(o.relayer, ZERO_ADDRESS)) warnings.push('any submitter may settle this order and earn the relayer share');
+  return { digest, minFill, warnings };
 }
diff --git a/clients/clientkeys/src/passkey-signer.js b/clients/clientkeys/src/passkey-signer.js
index 8035647..8d0ad51 100644
--- a/clients/clientkeys/src/passkey-signer.js
+++ b/clients/clientkeys/src/passkey-signer.js
@@ -2,5 +2,6 @@
 export * from './webauthn.js';
 export {
   hashTypedData, passkeySubjectKey, secpSubjectKey, accountSignature, merkleBatch, checkOwnerCall, checkPayment, keyProofMessage,
+  checkCall, checkTradeOrder, metaTransferTypedData, tradeOrderTypedData, orderCancelTypedData,
 } from './evm.js';
 export { b64url, fromB64url, hex, fromHex } from './bytes.js';
diff --git a/clients/clientkeys/src/seed-signer.js b/clients/clientkeys/src/seed-signer.js
index c19432c..70cbe8e 100644
--- a/clients/clientkeys/src/seed-signer.js
+++ b/clients/clientkeys/src/seed-signer.js
@@ -4,5 +4,6 @@ export { createVault, openVault, enablePrf, needsRewrap, rewrapPin, checkPassphr
 export { SeedBackup } from './backup.js';
 export {
   hashTypedData, secpSubjectKey, passkeySubjectKey, accountSignature, merkleBatch, checkOwnerCall, checkPayment, keyProofMessage,
+  checkCall, checkTradeOrder, metaTransferTypedData, tradeOrderTypedData, orderCancelTypedData,
 } from './evm.js';
 export { b64url, fromB64url, hex, fromHex, wipe } from './bytes.js';
diff --git a/clients/clientkeys/test/evm.test.js b/clients/clientkeys/test/evm.test.js
index 075c331..84ba5da 100644
--- a/clients/clientkeys/test/evm.test.js
+++ b/clients/clientkeys/test/evm.test.js
@@ -3,32 +3,61 @@ import assert from 'node:assert/strict';
 import { readFileSync } from 'node:fs';
 import { secp256k1 } from '@noble/curves/secp256k1.js';
 import {
-  hashTypedData, secpSubjectKey, accountSalt, predictAccount, accountSignature, merkleBatch, processProof,
+  hashTypedData, hashStruct, secpSubjectKey, accountSalt, predictAccount, accountSignature, merkleBatch, processProof,
   batchLeaf, evmAddress, passkeySubjectKey, addKeyCalldata, ownerCallTypedData, checkOwnerCall, checkPayment,
-  keyProofMessage, metaTxTypedData,
+  keyProofMessage, metaTxTypedData, metaTransferTypedData, checkCall, tradeOrderTypedData, orderCancelTypedData,
+  checkTradeOrder,
 } from '../src/evm.js';
 import { abiEncode, hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';
 
 const vectors = new URL('../../../smartcontracts/evm/test/vectors/', import.meta.url);
 const read = (f) => JSON.parse(readFileSync(new URL(f, vectors)));
 
-test('EIP-712 digest of the typed data Odoo issues = MetaTx KAT (MetaTxKat.t.sol)', () => {
-  const k = read('metatx_v1_kat.json');
-  const td = {
-    types: {
-      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
-        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
-      MetaTransaction: ['from:address', 'to:address', 'value:uint256', 'data:bytes', 'batch:uint256', 'nonce:uint256',
-        'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256', 'feeRecipient:address']
-        .map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })),
-    },
-    primaryType: 'MetaTransaction',
-    domain: { name: k.domain_name, version: k.domain_version, chainId: Number(k.chain_id), verifyingContract: k.verifying_contract },
-    // mode 1: relayer bound, feeRecipient canonical-zeroed (as dms_blockchain/lib/eip712.typed_data does).
-    message: { from: k.from, to: k.to, value: k.value, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until,
-      mode: Number(k.mode), relayer: k.relayer, fee: k.fee, feeRecipient: '0x' + '00'.repeat(20) },
-  };
+test('MetaTransfer payment = forge KAT (TokenKat.t.sol, metatransfer_kat.json)', () => {
+  const k = read('metatransfer_kat.json');   // mode 35: relayer and fee recipient bound, FIXED fee
+  const td = metaTransferTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id, chainUid: k.salt,
+    message: { from: k.from, to: k.to, value: k.value, entryRef: k.entry_ref, batch: k.batch, nonce: k.nonce,
+      validUntil: k.valid_until, mode: Number(k.mode), relayer: k.relayer, fee: k.fee, feeRecipient: k.fee_recipient } });
   assert.equal(hex(hashTypedData(td)), k.digest);
+  const unbound = metaTransferTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id,
+    chainUid: k.salt, message: { ...td.message, mode: 0x20 } });
+  assert.equal(unbound.message.feeRecipient, '0x' + '00'.repeat(20), 'unbound fields are hashed as 0');
+});
+
+/** `abi.encode(TradeOrder)` (13 static words) as forge wrote it into the KATs. */
+function decodeOrder(abi) {
+  const w = (i) => fromHex(abi).subarray(32 * i, 32 * i + 32);
+  const addr = (i) => hex(w(i).subarray(12));
+  const num = (i) => BigInt(hex(w(i))).toString();
+  return { from: addr(0), receiveToken: addr(1), amount: num(2), receiveAmount: num(3), minFill: num(4), fee: num(5),
+    relayer: addr(6), dex: addr(7), destination: addr(8), flags: Number(num(9)), batch: num(10), nonce: num(11),
+    validUntil: num(12) };
+}
+
+test('TradeOrder, CancelOrder, InvalidateNonces in the token domain = forge KAT (TradeKat.t.sol, trade_kat.json)', () => {
+  const k = read('trade_kat.json');
+  const o = decodeOrder(k.order_abi);
+  const td = tradeOrderTypedData({ token: k.verifying_contract, chainId: 7622, chainUid: k.salt, order: o });
+  assert.equal(hex(hashTypedData(td)), k.order_hash);
+  const at = { contract: k.verifying_contract, chainId: 7622, chainUid: k.salt };
+  assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, orderHash: k.order_hash }))), k.cancel_digest);
+  assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, invalidate: { from: o.from, batch: 7, minNonce: 43 } }))),
+    k.invalidate_digest);
+});
+
+test('DexOrder (nested TradeOrder) and the DEX cancels in the DEX domain = forge KAT (DexKat.t.sol, dex_order_kat.json)', () => {
+  const k = read('dex_order_kat.json');
+  const o = decodeOrder(k.maker_order_abi);
+  const td = tradeOrderTypedData({ dex: k.dex, sellToken: k.outside_token, chainId: 7622, chainUid: k.salt, order: o });
+  assert.equal(hex(hashStruct(td.types, 'DexOrder', td.message)), k.dex_order_struct_hash);
+  assert.equal(hex(hashTypedData(td)), k.dex_order_hash);
+  const at = { name: 'SCaaS Dex', contract: k.dex, chainId: 7622, chainUid: k.salt };
+  assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, orderHash: k.dex_order_hash }))), k.cancel_digest);
+  assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, invalidate: { from: o.from, batch: 1, minNonce: 5 } }))),
+    k.invalidate_digest);
+  const t = decodeOrder(k.taker_order_abi);
+  assert.equal(hex(hashTypedData(tradeOrderTypedData({ token: k.token, chainId: 7622, chainUid: k.salt, order: t }))),
+    k.taker_order_hash);
 });
 
 test('SmartKeyAccount owner call = forge KAT (AccountKat.t.sol, smart_key_account_kat.json)', () => {
@@ -230,53 +259,114 @@ function concatSel(sig) {
   return new Uint8Array([...keccak_256(utf8ToBytes(sig)).subarray(0, 4), ...new Uint8Array(96)]);
 }
 
-/** MetaTransaction exactly as Odoo `eip712.typed_data` issues it for a pay. */
-function odooPayment(over = {}, dom = {}) {
-  const k = read('metatx_v1_kat.json');
-  return {
-    types: {
-      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
-        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
-      MetaTransaction: ['from:address', 'to:address', 'value:uint256', 'data:bytes', 'batch:uint256', 'nonce:uint256',
-        'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256', 'feeRecipient:address']
-        .map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })),
-    },
-    primaryType: 'MetaTransaction',
-    domain: { name: 'SCaaS MetaToken', version: '1', chainId: 31337, verifyingContract: k.verifying_contract, ...dom },
-    message: { from: ACCOUNT, to: '0x' + '5e'.repeat(20), value: '125000500000', data: hex(concatPay()), batch: '7',
-      nonce: '0', validUntil: String(NOW + 300), mode: 1, relayer: '0x' + '02'.repeat(20), fee: '0',
-      feeRecipient: '0x' + '00'.repeat(20), ...over },
-  };
-}
+const TOKEN = '0x' + 'cd'.repeat(20);
+const REF = '0x' + '09'.repeat(32);
 
-function concatPay() {
-  return new Uint8Array([...keccak_256(utf8ToBytes('pay(bytes32)')).subarray(0, 4), ...new Uint8Array(32).fill(9)]);
+/** A payment `MetaTransfer` as a server issues it, in the token's salted domain. */
+function serverPayment(over = {}, dom = {}) {
+  const td = metaTransferTypedData({ contract: TOKEN, chainId: 7622, chainUid: UID, message: { from: ACCOUNT,
+    to: '0x' + '5e'.repeat(20), value: '125000500000', entryRef: REF, batch: '7', nonce: '0', validUntil: String(NOW + 300),
+    mode: 1, relayer: '0x' + '02'.repeat(20), ...over } });
+  td.domain = { ...td.domain, ...dom };
+  return td;
 }
 
-test('payment: the client signs only a pay of the amount it showed, from its own account, on its chain', () => {
-  const intent = { account: ACCOUNT, chainId: 31337, amount: 125000.5, decimals: 6, now: NOW };
-  const td = odooPayment();
+test('payment: the client signs only a MetaTransfer of the amount it showed, from its account, on its chain', () => {
+  const intent = { account: ACCOUNT, chainId: 7622, chainUid: UID, amount: 125000.5, decimals: 6, now: NOW };
+  const td = serverPayment();
   const ok = checkPayment(td, intent);
   assert.equal(hex(ok.digest), hex(hashTypedData(td)));
   assert.equal(ok.payee, '0x' + '5e'.repeat(20));
-  checkPayment(odooPayment({ value: '125000000000' }), { ...intent, amount: 125000 });
-  checkPayment(odooPayment({ mode: 0, relayer: '0x' + '00'.repeat(20) }), intent);
+  assert.equal(ok.entryRef, REF);
+  checkPayment(serverPayment({ value: '125000000000' }), { ...intent, amount: 125000 });
+  checkPayment(serverPayment({ mode: 0, relayer: '0x' + '00'.repeat(20) }), intent);
+  checkPayment(td, { ...intent, entryRef: REF, expectedToken: TOKEN });
+  assert.throws(() => checkPayment(td, { ...intent, expectedToken: '0x' + 'ce'.repeat(20) }), /wrong token/, 'CLI-SGN-08');
+  const unsalted = serverPayment();
+  unsalted.types = { ...unsalted.types, EIP712Domain: unsalted.types.EIP712Domain.slice(0, 4) };
+  delete unsalted.domain.salt;
+  const v1 = { ...serverPayment(), primaryType: 'MetaTransaction' };
   const refused = [
-    odooPayment({ value: '125000500001' }),                       // more than shown
-    odooPayment({ from: '0x' + 'bd'.repeat(20) }),
-    odooPayment({ data: hex(concatSel('trade(address,uint256,address)')) }),
-    odooPayment({ data: '0x' }),
-    odooPayment({ fee: '1' }),
-    odooPayment({ validUntil: String(NOW - 1) }),
-    odooPayment({ validUntil: String(NOW + 8 * 86400) }),
-    odooPayment({}, { chainId: 1 }),
-    odooPayment({}, { verifyingContract: ACCOUNT }),
+    serverPayment({ value: '125000500001' }),                       // more than shown
+    serverPayment({ from: '0x' + 'bd'.repeat(20) }),
+    serverPayment({ entryRef: '0x' + '00'.repeat(32) }),             // a plain transfer, not a payment
+    serverPayment({ fee: '1', mode: 0x21 }),
+    serverPayment({ validUntil: String(NOW - 1) }),
+    serverPayment({ validUntil: String(NOW + 8 * 86400) }),
+    serverPayment({}, { chainId: '1' }),
+    serverPayment({}, { verifyingContract: ACCOUNT }),
+    serverPayment({}, { salt: '0x' + '11'.repeat(32) }),             // another chain_uid (CLI-SGN-33)
+    unsalted,
+    v1,                                                              // the v1 struct
   ];
   for (const [i, bad] of refused.entries()) assert.throws(() => checkPayment(bad, intent), /Refusing to sign/, `case ${i}`);
+  assert.throws(() => checkPayment(td, { ...intent, entryRef: '0x' + '08'.repeat(32) }), /reference differs/);
   assert.throws(() => checkPayment(td, { ...intent, amount: 1e21 }), /Refusing to sign/);
-  // an owner call disguised as a payment, on the payment's own chain: its contract is the account, not a token
-  assert.throws(() => checkPayment(serverOwnerCall(addKeyCalldata(NEW_KEY), { chainId: 31337 }), intent),
-    /Refusing to sign: wrong token/);
+  // an owner call disguised as a payment, on the payment's own chain: its struct is a MetaTransaction
+  assert.throws(() => checkPayment(serverOwnerCall(addKeyCalldata(NEW_KEY)), intent), /Refusing to sign: this is not a payment/);
+});
+
+test('self-call: decoded against the published allowlist; transfers, payments and approvals are never calls', () => {
+  const k = read('metatx_kat.json');   // cancelNonce(42), relayer bound
+  const allowlist = [{ selector: '0xcfdd7aea', name: 'cancelNonce', feeClass: 1 }];
+  const want = { account: k.from, chainId: 7622, chainUid: k.salt, allowlist, now: 1_800_000_000 };
+  const call = (over = {}) => metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: 7622,
+    chainUid: k.salt, message: { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until,
+      mode: Number(k.mode), relayer: k.relayer, ...over } });
+  const ok = checkCall(call(), want);
+  assert.equal(hex(ok.digest), k.digest);
+  assert.equal(ok.name, 'cancelNonce');
+  const word = (n) => n.toString(16).padStart(64, '0');
+  for (const [i, data] of [
+    '0x12345678' + word(1),                                          // not on the allowlist
+    '0xa9059cbb' + word(1) + word(2),                                // transfer
+    '0x095ea7b3' + word(1) + word(2),                                // approve
+    '0x23b872dd' + word(1) + word(2) + word(3),                      // transferFrom
+    '0x',
+  ].entries()) {
+    assert.throws(() => checkCall(call({ data }), { ...want, allowlist: [...allowlist,
+      { selector: '0xa9059cbb', name: 'transfer', feeClass: 2 }, { selector: '0x095ea7b3', name: 'approve', feeClass: 1 }] }),
+    /Refusing to sign/, `case ${i}`);
+  }
+  assert.throws(() => checkCall(call({ mode: 0x11 }), want), /percentage fee/);
+  assert.throws(() => checkCall(call(), { ...want, chainUid: '0x' + '11'.repeat(32) }), /unexpected call fields/);
+  assert.throws(() => checkCall(call({ from: ACCOUNT }), want), /not from your account/);
+});
+
+test('trade order: only a DEX on the pinned list, a wrap only into a pinned wrapper (CLI-SGN-35, CLI-SGN-36)', () => {
+  const DEX = '0x' + 'de'.repeat(20);
+  const WRAPPER = '0x' + 'aa'.repeat(20);
+  const order = { from: ACCOUNT, receiveToken: '0x' + 'bb'.repeat(20), amount: '1000', receiveAmount: '2000', minFill: '0',
+    fee: '3000', relayer: '0x' + '02'.repeat(20), dex: DEX, destination: '0x' + '00'.repeat(20), flags: 0, batch: '1',
+    nonce: '1', validUntil: String(NOW + 600) };
+  const want = { account: ACCOUNT, chainId: 7622, chainUid: UID, dexes: [DEX], wrappers: [WRAPPER], now: NOW };
+  const td = (o, outside) => outside
+    ? tradeOrderTypedData({ dex: o.dex, sellToken: '0x' + '0c'.repeat(20), chainId: 7622, chainUid: UID, order: o })
+    : tradeOrderTypedData({ token: TOKEN, chainId: 7622, chainUid: UID, order: o });
+  const ok = checkTradeOrder(td(order), want);
+  assert.deepEqual(ok.warnings, []);
+  assert.equal(ok.minFill, 500n, 'a minFill below half is shown as half');
+  assert.equal(hex(ok.digest), hex(hashTypedData(td(order))));
+  checkTradeOrder(td(order, true), want);
+  assert.deepEqual(checkTradeOrder(td({ ...order, destination: '0x' + '77'.repeat(20) }), want).warnings,
+    ['someone else receives the proceeds']);
+  // a wrap by signature: dex = receiveToken = the wrapper, all or nothing
+  checkTradeOrder(td({ ...order, dex: WRAPPER, receiveToken: WRAPPER, minFill: '1000' }), want);
+  const refused = [
+    td({ ...order, dex: '0x' + 'ee'.repeat(20) }),                   // unlisted DEX
+    td({ ...order, dex: WRAPPER, receiveToken: WRAPPER }),           // a wrap that is not all or nothing
+    td({ ...order, dex: WRAPPER, minFill: '1000' }),                 // a wrap paying out something else
+    td({ ...order, fee: '10001' }),
+    td({ ...order, flags: 2 }),                                      // ESCROW without IOC
+    td({ ...order, flags: 8 }),
+    td({ ...order, minFill: '1001' }),
+    td({ ...order, from: '0x' + 'bd'.repeat(20) }),
+    td({ ...order, validUntil: String(NOW - 1) }),
+  ];
+  const wrongDex = td(order, true);
+  wrongDex.domain = { ...wrongDex.domain, verifyingContract: '0x' + 'ee'.repeat(20) };
+  refused.push(wrongDex);                                            // a DexOrder signed for another DEX
+  for (const [i, bad] of refused.entries()) assert.throws(() => checkTradeOrder(bad, want), /Refusing to sign/, `case ${i}`);
 });
 
 const KEY_PROOF_ZERO = '0xfa7987471ecf88572865d4f53880fda17e67fadcae78beb98eb39504833f66de';
``````


### Task 6: The v1 line to `legacy/p5/` (contracts, tests, vectors, deploy path, node and clientkeys encoders)

Nothing reads the v1 line after Tasks 2–5 (owner: backup, not delete; every chain is a test chain: redeploy, no
migration). The v1 sources, tests, vectors and the Hedera smoke move by `git mv`; files that mixed v1 and v2 are cut
(`FeePolicy.t.sol` → `legacy/p5/test/FeePolicyV1.t.sol`, `SmartKeyAccount.t.sol` → `legacy/p5/test/account/SmartKeyAccountV1.t.sol`,
`Mocks.sol`'s `MockZetherImpl` → `legacy/p5/test/helpers/MockZetherImpl.sol`); `MetaTxLib.LegacyMetaTransaction`
leaves the library (the file is backed up first); `MetaTxGasV2.t` is backed up, then compares v2 with the v1 numbers
frozen from `main` `e468d8c` (N14); `Deploy.s.sol` / `DeployHedera.s.sol` deploy no v1 contract; the node's and
clientkeys' v1 encoders are copied to their `legacy/p5/`; the e2e asserts the v1 deploy keys are gone.

**Files:** see Step 1 (moves and copies) and the diff.

- [ ] **Step 1: Moves and backup copies.**
  ```bash
  cd smartcontracts/evm
  mkdir -p legacy/p5/src/common legacy/p5/src/dex legacy/p5/src/factory legacy/p5/src/hedera legacy/p5/src/metatx legacy/p5/script/hedera legacy/p5/test/account legacy/p5/test/hedera legacy/p5/test/helpers legacy/p5/test/v2 legacy/p5/test/vectors
  /usr/bin/git mv script/hedera/HederaSmoke.sol legacy/p5/script/hedera/HederaSmoke.sol
  /usr/bin/git mv script/hedera/testnet_smoke.py legacy/p5/script/hedera/testnet_smoke.py
  /usr/bin/git mv src/common/IOpenFactoryV1.sol legacy/p5/src/common/IOpenFactoryV1.sol
  /usr/bin/git mv src/dex/MetaTxDex.sol legacy/p5/src/dex/MetaTxDex.sol
  /usr/bin/git mv src/dex/SCaaSDexV1.sol legacy/p5/src/dex/SCaaSDexV1.sol
  /usr/bin/git mv src/factory/IFactoryTokenV1.sol legacy/p5/src/factory/IFactoryTokenV1.sol
  /usr/bin/git mv src/factory/OpenFactoryV1.sol legacy/p5/src/factory/OpenFactoryV1.sol
  /usr/bin/git mv src/hedera/HederaMetaToken.sol legacy/p5/src/hedera/HederaMetaToken.sol
  /usr/bin/git mv src/metatx/ERC20MetaTxV1.sol legacy/p5/src/metatx/ERC20MetaTxV1.sol
  /usr/bin/git mv src/metatx/IERC20MetaTxV1.sol legacy/p5/src/metatx/IERC20MetaTxV1.sol
  /usr/bin/git mv src/metatx/IERC20PaymentV1.sol legacy/p5/src/metatx/IERC20PaymentV1.sol
  /usr/bin/git mv src/metatx/MetaToken.sol legacy/p5/src/metatx/MetaToken.sol
  /usr/bin/git mv test/ContractOnlyAllowance.t.sol legacy/p5/test/ContractOnlyAllowance.t.sol
  /usr/bin/git mv test/Erc1271.t.sol legacy/p5/test/Erc1271.t.sol
  /usr/bin/git mv test/Invariants.t.sol legacy/p5/test/Invariants.t.sol
  /usr/bin/git mv test/MetaApprove.t.sol legacy/p5/test/MetaApprove.t.sol
  /usr/bin/git mv test/MetaToken.t.sol legacy/p5/test/MetaToken.t.sol
  /usr/bin/git mv test/MetaTxDex.t.sol legacy/p5/test/MetaTxDex.t.sol
  /usr/bin/git mv test/MetaTxGas.t.sol legacy/p5/test/MetaTxGas.t.sol
  /usr/bin/git mv test/MetaTxKat.t.sol legacy/p5/test/MetaTxKat.t.sol
  /usr/bin/git mv test/OpenFactoryV1.t.sol legacy/p5/test/OpenFactoryV1.t.sol
  /usr/bin/git mv test/SCaaSDexV1.t.sol legacy/p5/test/SCaaSDexV1.t.sol
  /usr/bin/git mv test/SCaaSDexV1Invariant.t.sol legacy/p5/test/SCaaSDexV1Invariant.t.sol
  /usr/bin/git mv test/hedera/HederaMetaToken.t.sol legacy/p5/test/hedera/HederaMetaToken.t.sol
  /usr/bin/git mv test/helpers/Fixtures.sol legacy/p5/test/helpers/Fixtures.sol
  /usr/bin/git mv test/vectors/dex_kat.json legacy/p5/test/vectors/dex_kat.json
  /usr/bin/git mv test/vectors/metatx_v1_kat.json legacy/p5/test/vectors/metatx_v1_kat.json
  # backup copies (the files stay and are edited in Step 2)
  cp src/common/MetaTxLib.sol legacy/p5/src/common/MetaTxLib.sol
  cp test/v2/MetaTxGasV2.t.sol legacy/p5/test/v2/MetaTxGasV2.t.sol
  cd ../..
  # the node's and clientkeys' v1 encoders as they stand on main (not built)
  mkdir -p scaas-node/legacy/p5/dex clients/clientkeys/legacy/p5
  /usr/bin/git show e468d8c:scaas-node/src/abi.rs > scaas-node/legacy/p5/abi.rs
  /usr/bin/git show e468d8c:scaas-node/src/metatx.rs > scaas-node/legacy/p5/metatx.rs
  /usr/bin/git show e468d8c:scaas-node/src/dex.rs > scaas-node/legacy/p5/dex.rs
  /usr/bin/git show e468d8c:scaas-node/src/dex/venue.rs > scaas-node/legacy/p5/dex/venue.rs
  /usr/bin/git show e468d8c:scaas-node/tests/e2e.rs > scaas-node/legacy/p5/e2e.rs
  /usr/bin/git show e468d8c:clients/clientkeys/src/evm.js > clients/clientkeys/legacy/p5/evm.js
  ```
- [ ] **Step 2: Apply the diff below** (edits of the remaining files; the moved files are unchanged).
- [ ] **Step 3: Gates.** Full `forge build`, `forge test` 844 passed (1002 − 158 moved); size gate 0 errors; `FOUNDRY_PROFILE=private7622 forge build`;
  `cargo test --lib` 254 passed; clippy clean; e2e 4/4; e2e_hedera 1/1; clientkeys 60 / 58 / 2; nothing
  outside `legacy/` names the v1 line:
  `/usr/bin/grep -rln 'HederaMetaToken\|OpenFactoryV1\|MetaTxDex\|SCaaSDexV1\|metatx_v1_kat\|dex_kat\.json\|LegacyMetaTransaction\|import {MetaToken}' smartcontracts/evm/src smartcontracts/evm/test smartcontracts/evm/script scaas-node/src scaas-node/tests clients/clientkeys/src clients/clientkeys/test`
  prints only `script/Deploy.s.sol` and `script/hedera/DeployHedera.s.sol` (their header comments point at `legacy/p5/`;
  `executeMetaTransaction` stays: it is `MetaTxBase`'s v3 alias of `mtxExecute`).
- [ ] **Step 4: Commit** `P5 T6: the v1 line (MetaToken, HederaMetaToken, OpenFactoryV1, MetaTxDex, SCaaSDexV1, v1 KATs, deploy path) to legacy/p5; node and clientkeys v1 encoders backed up`.

``````diff
diff --git a/clients/clientkeys/legacy/p5/README.md b/clients/clientkeys/legacy/p5/README.md
new file mode 100644
index 0000000..42f8582
--- /dev/null
+++ b/clients/clientkeys/legacy/p5/README.md
@@ -0,0 +1,5 @@
+# legacy/p5 — reference only, not built
+
+`evm.js` as it stood before P5 (owner: backup, not delete): its `checkPayment` checked the v1 token's unsalted
+`MetaTransaction{from, to, value, data = pay(bytes32), …}` (vector `metatx_v1_kat.json`, now in
+`smartcontracts/evm/legacy/p5/test/vectors/`). Not exported, not tested, not bundled.
diff --git a/scaas-node/legacy/p5/README.md b/scaas-node/legacy/p5/README.md
new file mode 100644
index 0000000..efd29e6
--- /dev/null
+++ b/scaas-node/legacy/p5/README.md
@@ -0,0 +1,9 @@
+# legacy/p5 — reference only, not built
+
+The node's v1-line modules as they stood on `main` before P5 moved the node onto the token tree (owner: backup, not
+delete): `abi.rs` (the v1 `MetaTransaction` with `to`/`value`, `IMetaToken`, `IMetaTxDex`, v1 `IOpenFactory`),
+`metatx.rs` (its wire form and unsalted digest), `dex.rs` and `dex/venue.rs` (the order book in front of `SCaaSDexV1`:
+DEX-domain `Order`, `checkOrder`, `settle(Match[])`, allowances to the DEX), and `e2e.rs` (the e2e suite that drove
+them on the v1 deploy). Cargo builds only `src/` and `tests/`; nothing imports
+this directory. The contracts they spoke to are in `smartcontracts/evm/legacy/p5/`; their vectors
+(`metatx_v1_kat.json`, `dex_kat.json`) too.
diff --git a/scaas-node/tests/e2e.rs b/scaas-node/tests/e2e.rs
index e26de58..a4b9877 100644
--- a/scaas-node/tests/e2e.rs
+++ b/scaas-node/tests/e2e.rs
@@ -97,6 +97,11 @@ fn deploy(rpc: &str, chain_id: u64, holder: Address) -> Value {
     // P4: the account keys are `smart_key_account_*` (the node reads neither; Odoo seeds from them)
     assert!(dep["smart_key_account_factory"].is_string() && dep["smart_key_account_implementation"].is_string());
     assert!(dep.get("subject_account_factory").is_none(), "pre-P4 deploy JSON key");
+    // P5: the v1 line left the deploy (`legacy/p5/`); two demo tokens from the `OpenFactory`
+    for k in ["factory", "implementation", "dex", "scaas_dex"] {
+        assert!(dep.get(k).is_none(), "v1 deploy JSON key {k}");
+    }
+    assert!(dep["demo_token"].is_string() && dep["demo_token_2"].is_string());
     dep
 }
 
diff --git a/smartcontracts/evm/legacy/README.md b/smartcontracts/evm/legacy/README.md
index ab9681c..09cae2b 100644
--- a/smartcontracts/evm/legacy/README.md
+++ b/smartcontracts/evm/legacy/README.md
@@ -11,11 +11,11 @@ Hedera children, `OpenFactoryV2`) and the old `ZetherToken` with `ZetherMetaTx`,
 - The authoritative copy is the tag: `git show ref/pre-token-tree:smartcontracts/evm/src/<path>`.
 - Why it exists: owner decision of 2026-10-08 (CTR-MTX-07; TODO.md §00, P1 start checklist).
 - `p1e/`: `OpenFactoryV2`, `IOpenFactoryV2`, `IFactoryTokenV2` as they stood on `main` before P1e (the factory v2 that
-  P1e rewrote into `OpenFactory`); not built. (The v1 line follows into `legacy/` when node/clientkeys stop using it, P5, E1.)
+  P1e rewrote into `OpenFactory`); not built. (The v1 line followed in P5: `p5/`.)
 - `p3/`: the built `ZetherToken`, `ZetherMetaTx` and the old `IZetherToken` (384-byte statement header, own envelope,
   own underlying) with their tests (`ZetherToken.t`, `ZetherMulti.t`, `ZetherRevertPaths.t`, `ZetherGate.t` and the
   fixture), as they stood on `main` before P3 replaced them by the `*_ZETHER` kinds; not built. Nothing in the node or
-  the e2e read them. `OpenFactoryV1` keeps its `ZETHER` kind (mock-tested) until the v1 line moves (P5).
+  the e2e read them. `OpenFactoryV1` kept its `ZETHER` kind (mock-tested) until the v1 line moved (P5).
 - `p4/`: the built `SubjectAccount` and `SubjectAccountFactory` (typed `OwnerCall`, own nonce, domain `SCaaS SubjectAccount`
   without salt) and their test `SubjectAccount.t.sol`, as they stood on `main` before P4 put `SmartKeyAccount` on
   `MetaTxBase` (CTR-ACC-10, CTR-ACC-11); and the built `MandateWallet` / `HederaMandateWallet` (typed `PayUnderMandate`,
@@ -24,3 +24,13 @@ Hedera children, `OpenFactoryV2`) and the old `ZetherToken` with `ZetherMetaTx`,
   deployed from them keep working with their own code.
   The backed-up `SubjectAccount.t.sol` reads `test/vectors/subject_account_create2.json`, which is now
   `smart_key_account_create2.json` (only its `note` differs); restore the old name to run it.
+- `p5/`: the v1 line as it stood on `main` before P5 moved the node and clientkeys onto the token tree (E1; owner:
+  backup, not delete): `MetaToken`, `ERC20MetaTxV1`, `IERC20MetaTxV1`, `IERC20PaymentV1`, `HederaMetaToken`,
+  `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1`, `MetaTxDex`, `SCaaSDexV1`; their tests (`MetaToken.t`,
+  `MetaTxDex.t`, `MetaTxKat.t`, `OpenFactoryV1.t`, `SCaaSDexV1.t`, `SCaaSDexV1Invariant.t`, `MetaApprove.t`, `Erc1271.t`,
+  `Invariants.t`, `ContractOnlyAllowance.t`, `MetaTxGas.t`, `hedera/HederaMetaToken.t`, the v1 Hedera KAT test, the
+  `Fixtures` helper) and the tests cut from live files (`SmartKeyAccountV1.t`, `FeePolicyV1.t`, `MockZetherImpl`); the
+  vectors `metatx_v1_kat.json`, `dex_kat.json` and the v1 `hedera_kat.json`; the v1 Hedera smoke script; `MetaTxLib`
+  with its `LegacyMetaTransaction` and the v1/v2 gas table `MetaTxGasV2.t` as they were. The node's and clientkeys'
+  v1 modules are in `scaas-node/legacy/p5/` and `clients/clientkeys/legacy/p5/`. Nothing deployed: every chain is a
+  test chain and is redeployed.
diff --git a/smartcontracts/evm/legacy/p5/test/FeePolicyV1.t.sol b/smartcontracts/evm/legacy/p5/test/FeePolicyV1.t.sol
new file mode 100644
index 0000000..35f3dff
--- /dev/null
+++ b/smartcontracts/evm/legacy/p5/test/FeePolicyV1.t.sol
@@ -0,0 +1,20 @@
+// SPDX-License-Identifier: Apache-2.0
+// legacy/p5 — reference only, not built: cut from `test/FeePolicy.t.sol` when the v1 line left the build (P5).
+pragma solidity ^0.8.20;
+
+import {Test} from "forge-std/Test.sol";
+import {MetaTxLib} from "../src/common/MetaTxLib.sol";
+
+contract FeePolicyV1Test is Test {
+    /// Typehash là hợp đồng giữa contract và SDK client. Lệch một ký tự ⇒ hai digest
+    /// khác nhau ⇒ 100% chữ ký fail, và triệu chứng là "chữ ký sai" chứ không phải
+    /// "typehash lệch". Pin nó bằng test.
+    function test_legacyMetaTxTypehashIsPinned() public pure {
+        assertEq(
+            MetaTxLib.LEGACY_METATX_TYPEHASH,
+            keccak256(
+                "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
+            )
+        );
+    }
+}
diff --git a/smartcontracts/evm/legacy/p5/test/account/SmartKeyAccountV1.t.sol b/smartcontracts/evm/legacy/p5/test/account/SmartKeyAccountV1.t.sol
new file mode 100644
index 0000000..8849023
--- /dev/null
+++ b/smartcontracts/evm/legacy/p5/test/account/SmartKeyAccountV1.t.sol
@@ -0,0 +1,36 @@
+// SPDX-License-Identifier: Apache-2.0
+// legacy/p5 — reference only, not built: cut from `test/account/SmartKeyAccount.t.sol` when the v1 line left the build (P5).
+pragma solidity ^0.8.20;
+
+// The test ran inside `SmartKeyAccountTest` (fixtures `fac`, `acct`, `shop`, `relayer`, `RR`, `PASSKEY`, `_pk`).
+import {OpenFactoryV1} from "../src/factory/OpenFactoryV1.sol";
+import {IOpenFactoryV1} from "../src/common/IOpenFactoryV1.sol";
+import {MetaToken} from "../src/metatx/MetaToken.sol";
+import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
+
+abstract contract SmartKeyAccountV1Test {
+    /// v1 `MetaToken` (deployed with the new `IMPLEMENTATION` until P5 retires it) pays from a clone with a passkey,
+    /// also without the precompile, where only the clones' 400k ERC-1271 allowance fits the Solidity verifier.
+    function test_v1MetaTokenPaysFromCloneWithPasskey() public {
+        OpenFactoryV1 f1 = new OpenFactoryV1(address(0xF00D));
+        MetaToken impl1 = new MetaToken(address(f1), fac.IMPLEMENTATION());
+        vm.prank(address(0xF00D));
+        f1.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl1));
+        MetaToken t1 = MetaToken(f1.createMetaToken(1, address(0),
+            abi.encode("Token V", "V", uint8(0), uint256(1000), address(this)), keccak256("V")));
+        t1.transfer(address(acct), 1000);
+        vm.mockCallRevert(address(0x100), bytes(""), bytes(""));
+        for (uint256 i; i < 2; ++i) {
+            bytes32 ref = bytes32(i + 1);
+            MetaTxLib.LegacyMetaTransaction memory m = MetaTxLib.LegacyMetaTransaction({
+                from: address(acct), to: shop, value: 400, data: abi.encodeWithSignature("pay(bytes32)", ref),
+                batch: i, nonce: 0, validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0,
+                feeRecipient: address(0)});
+            bytes memory sig = _pk(0, PASSKEY, t1.metaTxDigest(m));
+            vm.prank(relayer);
+            t1.executeMetaTransaction(m, sig);
+            if (i == 0) vm.clearMockedCalls();          // the second with the precompile
+        }
+        assertEq(t1.balanceOf(shop), 800);
+    }
+}
diff --git a/smartcontracts/evm/legacy/p5/test/helpers/MockZetherImpl.sol b/smartcontracts/evm/legacy/p5/test/helpers/MockZetherImpl.sol
new file mode 100644
index 0000000..671becb
--- /dev/null
+++ b/smartcontracts/evm/legacy/p5/test/helpers/MockZetherImpl.sol
@@ -0,0 +1,19 @@
+// SPDX-License-Identifier: Apache-2.0
+// legacy/p5 — reference only, not built: cut from `test/helpers/Mocks.sol` when the v1 line left the build (P5).
+pragma solidity ^0.8.20;
+
+import {IFactoryTokenV1} from "../../src/factory/IFactoryTokenV1.sol";
+
+/// Implementation ZETHER giả: chỉ để chứng minh factory xử lý kind ZETHER qua cùng
+/// `IFactoryTokenV1`. Không có gì bảo mật ở đây.
+contract MockZetherImpl is IFactoryTokenV1 {
+    address public immutable FACTORY;
+    address public verifier;
+    bool private _done;
+    constructor(address f) { FACTORY = f; _done = true; }
+    function initialize(address, address, address verifier_, uint64, bytes calldata) external {
+        require(msg.sender == FACTORY && !_done, "init");
+        _done = true;
+        verifier = verifier_;
+    }
+}
diff --git a/smartcontracts/evm/script/Deploy.s.sol b/smartcontracts/evm/script/Deploy.s.sol
index c8bc5bb..2d01bba 100644
--- a/smartcontracts/evm/script/Deploy.s.sol
+++ b/smartcontracts/evm/script/Deploy.s.sol
@@ -2,14 +2,9 @@
 pragma solidity ^0.8.20;
 
 import {console} from "forge-std/Script.sol";
-import {OpenFactoryV1} from "../src/factory/OpenFactoryV1.sol";
-import {IOpenFactoryV1} from "../src/common/IOpenFactoryV1.sol";
-import {MetaToken} from "../src/metatx/MetaToken.sol";
-import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
+import {OpenFactory} from "../src/factory/OpenFactory.sol";
 import {SmartKeyAccountFactory} from "../src/account/SmartKeyAccountFactory.sol";
-import {SCaaSDexV1} from "../src/dex/SCaaSDexV1.sol";
 import {DeployBase} from "./DeployBase.sol";
-import {OpenFactory} from "../src/factory/OpenFactory.sol";
 
 /// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --sender <địa chỉ deployer = vm.addr(PRIVATE_KEY)>
 /// env: PRIVATE_KEY (deployer; registrar mặc định), REGISTRAR (tuỳ chọn),
@@ -17,7 +12,10 @@ import {OpenFactory} from "../src/factory/OpenFactory.sol";
 ///      DEPLOY_SALT (tuỳ chọn; mặc định keccak256("scaas.deploy.v1"); chạy lại trên cùng chain cần salt mới),
 ///      CHAIN_UID (genesis hash, chain-uids.json; tuỳ chọn; phải bằng hash block 0 của RPC, mặc định chính hash đó).
 ///      DEPLOY_ZETHER (tuỳ chọn, true/false; chỉ dev chain; cần cờ forge trong deploy.sh, docs/networks/evm.md).
-/// Ghi `deployments/<chainid>.json` để seed Odoo (`blockchain.token`) và config node (`dex`).
+/// Ghi `deployments/<chainid>.json` (token factory, implementations, the DEX implementation, the SmartKeyAccount
+/// factory, `chain_uid`, the demo tokens) để seed client (`blockchain.token`) và config node; a DEX is a clone from
+/// `OpenFactory.createDex` (CTR-DEX-24). The v1 line (`OpenFactoryV1`, `MetaToken`, `MetaTxDex`, `SCaaSDexV1`) is in
+/// `legacy/p5/` (P5).
 contract Deploy is DeployBase {
     function run() external {
         uint256 pk = vm.envUint("PRIVATE_KEY");
@@ -28,25 +26,15 @@ contract Deploy is DeployBase {
 
         _setup();
         vm.startBroadcast(pk);
-        OpenFactoryV1 factory = new OpenFactoryV1{salt: salt}(registrar);
         SmartKeyAccountFactory accounts = new SmartKeyAccountFactory{salt: salt}(uid);
         _gate(address(accounts));
-        MetaToken impl = new MetaToken{salt: salt}(address(factory), accounts.IMPLEMENTATION());
-        if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
         OpenFactory tokens = _deployTokenFactory(registrar, registrar == deployer, accounts.IMPLEMENTATION(), false);
-        MetaTxDex dex = new MetaTxDex{salt: salt}();
-        // R35: admin chỉ `setMarket`; production đặt REGISTRAR là một Safe (RS5-1).
-        SCaaSDexV1 scaasDex = new SCaaSDexV1{salt: salt}(registrar);
         if (demoSupply != 0 && registrar == deployer) _demoTokens(tokens, demoSupply, deployer, demoHolder);
         vm.stopBroadcast();
 
         string memory k = "deploy";
-        vm.serializeAddress(k, "factory", address(factory));
-        vm.serializeAddress(k, "implementation", address(impl));
-        vm.serializeAddress(k, "dex", address(dex));
         vm.serializeAddress(k, "smart_key_account_factory", address(accounts));
-        vm.serializeAddress(k, "smart_key_account_implementation", accounts.IMPLEMENTATION());
-        string memory out = vm.serializeAddress(k, "scaas_dex", address(scaasDex));
+        string memory out = vm.serializeAddress(k, "smart_key_account_implementation", accounts.IMPLEMENTATION());
         vm.createDir("./deployments", true);
         vm.writeJson(out, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
         console.log(out);
diff --git a/smartcontracts/evm/script/hedera/DeployHedera.s.sol b/smartcontracts/evm/script/hedera/DeployHedera.s.sol
index 34168df..448f9a1 100644
--- a/smartcontracts/evm/script/hedera/DeployHedera.s.sol
+++ b/smartcontracts/evm/script/hedera/DeployHedera.s.sol
@@ -2,19 +2,16 @@
 pragma solidity ^0.8.20;
 
 import {console} from "forge-std/Script.sol";
-import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
-import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
-import {MetaTxDex} from "../../src/dex/MetaTxDex.sol";
-import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
-import {DeployBase} from "../DeployBase.sol";
 import {OpenFactory} from "../../src/factory/OpenFactory.sol";
+import {DeployBase} from "../DeployBase.sol";
 
-/// Như `script/Deploy.s.sol` nhưng implementation META là `HederaMetaToken` (R63).
+/// Như `script/Deploy.s.sol` trên Hedera (R63): every implementation with `IS_HEDERA` (HIP-632 signatures, CTR-TOK-23),
+/// no `SmartKeyAccount` implementation (Hedera accounts are native), two demo tokens.
 /// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow --sender <địa chỉ deployer>`
 /// (relay không có mempool: `--slow` gửi tuần tự, mỗi tx chờ receipt). Deployer = tài khoản ECDSA có alias EVM.
 /// env: PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?, DEMO_HOLDER?, CHAIN_UID? (mặc định hash block 0 của RPC),
 ///      DEPLOY_SALT? (mặc định keccak256("scaas.deploy.v1"); chạy lại trên cùng chain cần salt mới).
-/// Ghi `deployments/hedera-<chainid>.json`.
+/// Ghi `deployments/hedera-<chainid>.json`. The v1 `HederaMetaToken` line is in `legacy/p5/` (P5).
 contract DeployHedera is DeployBase {
     function run() external {
         uint256 pk = vm.envUint("PRIVATE_KEY");
@@ -25,18 +22,11 @@ contract DeployHedera is DeployBase {
 
         _setup();
         vm.startBroadcast(pk);
-        OpenFactoryV1 factory = new OpenFactoryV1{salt: salt}(registrar);
-        HederaMetaToken impl = new HederaMetaToken{salt: salt}(address(factory));
-        if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
         OpenFactory tokens = _deployTokenFactory(registrar, registrar == deployer, address(0), true);
-        MetaTxDex dex = new MetaTxDex{salt: salt}();
         if (demoSupply != 0 && registrar == deployer) _demoTokens(tokens, demoSupply, deployer, demoHolder);
         vm.stopBroadcast();
 
-        string memory k = "deploy";
-        vm.serializeAddress(k, "factory", address(factory));
-        vm.serializeAddress(k, "implementation", address(impl));
-        string memory out = vm.serializeAddress(k, "dex", address(dex));
+        string memory out = vm.serializeString("deploy", "network", "hedera");
         vm.createDir("./deployments", true);
         vm.writeJson(out, string.concat("./deployments/hedera-", vm.toString(block.chainid), ".json"));
         console.log(out);
diff --git a/smartcontracts/evm/src/common/MetaTxLib.sol b/smartcontracts/evm/src/common/MetaTxLib.sol
index 6c97c20..36b665c 100644
--- a/smartcontracts/evm/src/common/MetaTxLib.sol
+++ b/smartcontracts/evm/src/common/MetaTxLib.sol
@@ -78,6 +78,17 @@ library MetaTxLib {
         "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
     );
 
+    /// @notice Chuẩn hoá hai trường do relayer điền, trước khi băm.
+    /// @dev Đây là quy tắc PHẢI giống hệt nhau ở ba nơi: verifier Solidity, SDK client,
+    ///      và builder phía Odoo. Lệch một chỗ thì mọi chữ ký fail — fail-closed nên
+    ///      không mất tiền, nhưng là một nguy cơ tích hợp phải nhớ mãi.
+    ///
+    ///      Chọn "băm với address(0)" chứ KHÔNG phải "bỏ trường khỏi struct". Lý do
+    ///      quyết định: `TYPEHASH` là hash của type string, và type string phải cố
+    ///      định. Bỏ trường ra khi MODE_OPEN nghĩa là một type KHÁC, cần một
+    ///      `TYPEHASH` thứ hai, và ví EIP-712 sẽ hiển thị hai loại giao dịch khác nhau
+    ///      cho cùng một hành động. Ngoài ra encoding độ dài thay đổi phá injectivity.
+    ///      Một type string, hai giá trị canonical.
     function canon(MetaTransaction memory m) internal pure returns (address r, address f) {
         r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
         f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
@@ -122,21 +133,6 @@ library MetaTxLib {
         ));
     }
 
-    /// @notice v1/v2 struct (Transitional, BUILT): deleted with the v1/v2 lines (P1b) and `ZetherMetaTx` (P3).
-    struct LegacyMetaTransaction {
-        address from;           // người ký, người chịu hiệu lực
-        address to;             // đích của thao tác trên chính token này
-        uint256 value;          // số lượng token cho thao tác (0 nếu chỉ gọi logic)
-        bytes   data;           // payload của thao tác
-        uint256 batch;          // nonce chiều 1 — luồng độc lập
-        uint256 nonce;          // nonce chiều 2 — thứ tự trong luồng
-        uint256 validUntil;     // hạn, giây epoch
-        uint32  mode;           // hai nửa byte: cờ ràng buộc + cách tính phí. Xem trên
-        address relayer;        // chỉ ràng buộc khi mode & MODE_RESTRICT_RELAYER
-        uint256 fee;            // ppm nếu PERCENT, tuyệt đối nếu FIXED, bỏ qua nếu NONE
-        address feeRecipient;   // chỉ ràng buộc khi mode & MODE_RESTRICT_FEE_RECIPIENT
-    }
-
     /// @notice Đọc cách tính phí từ nửa byte sau của `mode`.
     /// @dev Trả về `FeeMode` để `FeePolicy` dùng nguyên như cũ — enum vẫn là kiểu
     ///      chuẩn tắc của tầng phí, chỉ không còn là một trường riêng trong struct.
@@ -157,53 +153,4 @@ library MetaTxLib {
         if (mode & ~MODE_KNOWN_MASK != 0) revert ModeUnknownBits(mode);
         feeModeOf(mode);  // revert ModeFeeInvalid nếu nửa byte sau > 2
     }
-
-    /// @notice Chuẩn hoá hai trường do relayer điền, trước khi băm.
-    /// @dev Đây là quy tắc PHẢI giống hệt nhau ở ba nơi: verifier Solidity, SDK client,
-    ///      và builder phía Odoo. Lệch một chỗ thì mọi chữ ký fail — fail-closed nên
-    ///      không mất tiền, nhưng là một nguy cơ tích hợp phải nhớ mãi.
-    ///
-    ///      Chọn "băm với address(0)" chứ KHÔNG phải "bỏ trường khỏi struct". Lý do
-    ///      quyết định: `TYPEHASH` là hash của type string, và type string phải cố
-    ///      định. Bỏ trường ra khi MODE_OPEN nghĩa là một type KHÁC, cần một
-    ///      `TYPEHASH` thứ hai, và ví EIP-712 sẽ hiển thị hai loại giao dịch khác nhau
-    ///      cho cùng một hành động. Ngoài ra encoding độ dài thay đổi phá injectivity.
-    ///      Một type string, hai giá trị canonical.
-    function canon(LegacyMetaTransaction memory m)
-        internal pure returns (address r, address f)
-    {
-        r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
-        f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
-    }
-
-    /// @dev Thứ tự và kiểu ở đây phải khớp TỪNG KÝ TỰ với chuỗi type trong SDK client.
-    ///      Ghim bởi `test_legacyMetaTxTypehashIsPinned` — đổi một ký tự là đổi mọi digest đã
-    ///      phát hành, nên test phải fail chứ không được tự chỉnh theo.
-    bytes32 internal constant LEGACY_METATX_TYPEHASH = keccak256(
-        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
-    );
-
-    /// @notice structHash theo EIP-712.
-    /// @dev `bytes data` PHẢI được keccak, không encode thẳng. Bỏ là vỡ injectivity:
-    ///      `("ab","c")` và `("a","bc")` cho cùng một digest. Fuzz không tìm ra (xác
-    ///      suất 0); solver tìm ra trong vài giây.
-    function hashStruct(LegacyMetaTransaction memory m) internal pure returns (bytes32) {
-        (address r, address f) = canon(m);
-        return keccak256(
-            abi.encode(
-                LEGACY_METATX_TYPEHASH,
-                m.from,
-                m.to,
-                m.value,
-                keccak256(m.data),
-                m.batch,
-                m.nonce,
-                m.validUntil,
-                m.mode,
-                r,
-                m.fee,
-                f
-            )
-        );
-    }
 }
diff --git a/smartcontracts/evm/test/FeePolicy.t.sol b/smartcontracts/evm/test/FeePolicy.t.sol
index 126c03e..88e5c96 100644
--- a/smartcontracts/evm/test/FeePolicy.t.sol
+++ b/smartcontracts/evm/test/FeePolicy.t.sol
@@ -40,18 +40,6 @@ contract FeePolicyTest is Test {
         assertEq(FeePolicy.compute(FeeMode.NONE, 1_000_000, 999_999), 0);
     }
 
-    /// Typehash là hợp đồng giữa contract và SDK client. Lệch một ký tự ⇒ hai digest
-    /// khác nhau ⇒ 100% chữ ký fail, và triệu chứng là "chữ ký sai" chứ không phải
-    /// "typehash lệch". Pin nó bằng test.
-    function test_legacyMetaTxTypehashIsPinned() public pure {
-        assertEq(
-            MetaTxLib.LEGACY_METATX_TYPEHASH,
-            keccak256(
-                "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
-            )
-        );
-    }
-
     /// Nửa byte sau của `mode` là cách tính phí. Ba giá trị hợp lệ, phần còn lại phải
     /// revert — nếu không thì `0x30` hôm nay bị bỏ qua và ngữ nghĩa của nó ngày mai
     /// bị khoá chết bởi những chữ ký đã phát hành.
diff --git a/smartcontracts/evm/test/account/SmartKeyAccount.t.sol b/smartcontracts/evm/test/account/SmartKeyAccount.t.sol
index 571f4f2..6f20774 100644
--- a/smartcontracts/evm/test/account/SmartKeyAccount.t.sol
+++ b/smartcontracts/evm/test/account/SmartKeyAccount.t.sol
@@ -13,9 +13,6 @@ import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
 import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
 import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
 import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
-import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
-import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
-import {MetaToken} from "../../src/metatx/MetaToken.sol";
 
 /// Software authenticator: a fixed P-256 key, authenticatorData/clientDataJSON in the WebAuthn format (L3 §5.8.1.1),
 /// the signature normalised to low-s as clients do.
@@ -401,31 +398,6 @@ contract SmartKeyAccountTest is WebAuthnSoft {
         assertEq(acct.keyCount(), 2);
     }
 
-    /// v1 `MetaToken` (deployed with the new `IMPLEMENTATION` until P5 retires it) pays from a clone with a passkey,
-    /// also without the precompile, where only the clones' 400k ERC-1271 allowance fits the Solidity verifier.
-    function test_v1MetaTokenPaysFromCloneWithPasskey() public {
-        OpenFactoryV1 f1 = new OpenFactoryV1(address(0xF00D));
-        MetaToken impl1 = new MetaToken(address(f1), fac.IMPLEMENTATION());
-        vm.prank(address(0xF00D));
-        f1.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl1));
-        MetaToken t1 = MetaToken(f1.createMetaToken(1, address(0),
-            abi.encode("Token V", "V", uint8(0), uint256(1000), address(this)), keccak256("V")));
-        t1.transfer(address(acct), 1000);
-        vm.mockCallRevert(address(0x100), bytes(""), bytes(""));
-        for (uint256 i; i < 2; ++i) {
-            bytes32 ref = bytes32(i + 1);
-            MetaTxLib.LegacyMetaTransaction memory m = MetaTxLib.LegacyMetaTransaction({
-                from: address(acct), to: shop, value: 400, data: abi.encodeWithSignature("pay(bytes32)", ref),
-                batch: i, nonce: 0, validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0,
-                feeRecipient: address(0)});
-            bytes memory sig = _pk(0, PASSKEY, t1.metaTxDigest(m));
-            vm.prank(relayer);
-            t1.executeMetaTransaction(m, sig);
-            if (i == 0) vm.clearMockedCalls();          // the second with the precompile
-        }
-        assertEq(t1.balanceOf(shop), 800);
-    }
-
     // ------------------------------------------------------------------ key management (CTR-ACC-10)
 
     function test_never_zero_keys() public {
diff --git a/smartcontracts/evm/test/helpers/Mocks.sol b/smartcontracts/evm/test/helpers/Mocks.sol
index cbd46fd..6eab803 100644
--- a/smartcontracts/evm/test/helpers/Mocks.sol
+++ b/smartcontracts/evm/test/helpers/Mocks.sol
@@ -2,7 +2,6 @@
 pragma solidity ^0.8.20;
 
 import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
-import {IFactoryTokenV1} from "../../src/factory/IFactoryTokenV1.sol";
 
 contract MockERC20 is ERC20 {
     uint8 private immutable _d;
@@ -33,17 +32,3 @@ contract UnsupportedVerifier {
     function isSupportedOnThisChain() external pure returns (bool) { return false; }
     function curveName() external pure returns (string memory) { return "bls12-381"; }
 }
-
-/// Implementation ZETHER giả: chỉ để chứng minh factory xử lý kind ZETHER qua cùng
-/// `IFactoryTokenV1`. Không có gì bảo mật ở đây.
-contract MockZetherImpl is IFactoryTokenV1 {
-    address public immutable FACTORY;
-    address public verifier;
-    bool private _done;
-    constructor(address f) { FACTORY = f; _done = true; }
-    function initialize(address, address, address verifier_, uint64, bytes calldata) external {
-        require(msg.sender == FACTORY && !_done, "init");
-        _done = true;
-        verifier = verifier_;
-    }
-}
diff --git a/smartcontracts/evm/test/v2/MetaTxGasV2.t.sol b/smartcontracts/evm/test/v2/MetaTxGasV2.t.sol
index 731af04..1b60284 100644
--- a/smartcontracts/evm/test/v2/MetaTxGasV2.t.sol
+++ b/smartcontracts/evm/test/v2/MetaTxGasV2.t.sol
@@ -2,15 +2,11 @@
 pragma solidity ^0.8.20;
 
 import {Test, console} from "forge-std/Test.sol";
-import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
-import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
-import {MetaToken} from "../../src/metatx/MetaToken.sol";
 import {OpenFactory} from "../../src/factory/OpenFactory.sol";
 import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
 import {NormalToken} from "../../src/metatx/NormalToken.sol";
 import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
 import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
-import {IERC20MetaTxV1} from "../../src/metatx/IERC20MetaTxV1.sol";
 import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
 import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
 import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
@@ -21,9 +17,11 @@ contract Always1271 {
     function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) { return 0x1626ba7e; }
 }
 
-/// @title Bảng gas v2 so với v1 (TW2 §10.3): clone `MetaToken` v1 và clone `NormalToken` v2, cùng kịch bản.
-/// @notice v1 = `executeMetaTransaction` (legacy struct); v2 = `mtxExecuteTransfer` (`MetaTransfer`), named builders,
-///         `mtxExecute` (self-call). Ngân sách: mọi hàng của đường chung ≤ v1 + 300; hàm có tên ≤ đường chung cùng
+/// @title Bảng gas v2 so với v1 (TW2 §10.3): clone `NormalToken` v2 against the v1 numbers frozen at P5.
+/// @notice v1 = `executeMetaTransaction` (legacy struct) on a `MetaToken` clone, measured by this file's pre-P5 version
+///         (`legacy/p5/test/v2/MetaTxGasV2.t.sol`) on main `e468d8c` and frozen in the `V1_*` constants: the v1 line
+///         left the build in P5. v2 = `mtxExecuteTransfer` (`MetaTransfer`), named builders, `mtxExecute`
+///         (self-call). Ngân sách: mọi hàng của đường chung ≤ v1 + 300; hàm có tên ≤ đường chung cùng
 ///         intent. A row that no longer holds logs both numbers (`log_named_uint`) instead of asserting.
 ///         Cùng một hàm test đo nhiều lần nên phải `vm.cool` mọi địa chỉ chạm tới trước mỗi lần đo (EIP-2929 không
 ///         reset giữa các lời gọi trong một hàm test — xem `MetaTxGas.t.sol`), và mỗi lần đo chạy trên một token RIÊNG
@@ -35,11 +33,20 @@ contract MetaTxGasV2Test is Test {
     uint256 constant BUDGET = 300;
     uint256 constant WARM = 1;
     uint256 constant COLD = 2;
+    // v1 `executeMetaTransaction` per row, frozen at P5 (see the title)
+    uint256 constant V1_A = 36_017;
+    uint256 constant V1_B = 53_117;
+    uint256 constant V1_C = 44_329;
+    uint256 constant V1_D = 44_275;
+    uint256 constant V1_E = 44_521;
+    uint256 constant V1_F = 53_117;
+    uint256 constant V1_G = 50_762;
+    uint256 constant V1_P = 58_040;
+    uint256 constant V1_H = 23_142;
     address signer;
     address relayer = address(0xBEEF);
     address recipient = address(0xCAFE);
     address feeTaker = address(0xFEE);
-    MetaToken v1;
     NormalToken v2;
     NormalToken v2b; // same state as v2, for the named-vs-generic rows
     NormalToken v2c;
@@ -50,9 +57,6 @@ contract MetaTxGasV2Test is Test {
     function setUp() public {
         vm.warp(1_800_000_000);
         signer = vm.addr(PK);
-        OpenFactoryV1 f1 = new OpenFactoryV1(address(this));
-        f1.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(new MetaToken(address(f1), address(0))));
-        v1 = MetaToken(f1.createMetaToken(1, address(0), abi.encode("V1", "V1", uint8(18), uint256(0), address(this)), "a"));
         OpenFactory f2 = new OpenFactory(address(this), UID);
         f2.registerImplementation(IOpenFactory.TokenKind.NORMAL, 1,
             address(new NormalToken(address(f2), address(0), UID, false)));
@@ -62,7 +66,6 @@ contract MetaTxGasV2Test is Test {
         v2 = _v2(f2, "a");
         v2b = _v2(f2, "b");
         v2c = _v2(f2, "c");
-        _fund(address(v1));
         // a 1:1 wrapper for the wrap / unwrap rows
         usdc = new MockERC20("USD Coin", "USDC", 6);
         address[] memory us = new address[](1);
@@ -91,8 +94,7 @@ contract MetaTxGasV2Test is Test {
     function _fund(address t) internal {
         address[5] memory holders = [signer, recipient, relayer, address(acct), feeTaker];
         for (uint256 i; i < 5; ++i) NormalToken(t).mint(holders[i], i == 0 ? 1_000_000 ether : 1 ether);
-        if (t == address(v1)) _exec(t, _mt(0, WARM, 0, 0, address(0)));
-        else _execT(t, _x(_mt(0, WARM, 0, 0, address(0))));
+        _execT(t, _mt(0, WARM, 0, 0, address(0)));
     }
 
     /// Calldata `sel(words..., bytes sig)` dựng tay: bộ mã hoá ABI không via-IR hết stack với 10–11 tham số
@@ -102,26 +104,15 @@ contract MetaTxGasV2Test is Test {
             new bytes((32 - sig.length % 32) % 32));
     }
 
+    /// The v1 rows' intent as a `MetaTransfer`: `value` 1 ether to `recipient`, `entryRef` 0.
     function _mt(uint32 mode, uint256 batch, uint256 nonce, uint256 fee, address feeRcpt)
-        internal view returns (MetaTxLib.LegacyMetaTransaction memory m)
+        internal view returns (MetaTxLib.MetaTransfer memory)
     {
-        m = MetaTxLib.LegacyMetaTransaction({from: signer, to: recipient, value: 1 ether, data: "", batch: batch,
+        return MetaTxLib.MetaTransfer({from: signer, to: recipient, value: 1 ether, entryRef: 0, batch: batch,
             nonce: nonce, validUntil: block.timestamp + 600, mode: mode, relayer: relayer, fee: fee,
             feeRecipient: feeRcpt});
     }
 
-    function _sig(address t, MetaTxLib.LegacyMetaTransaction memory m) internal view returns (bytes memory) {
-        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, IERC20MetaTxV1(t).metaTxDigest(m));
-        return abi.encodePacked(r, s, v);
-    }
-
-    /// The same intent as a `MetaTransfer` (v2).
-    function _x(MetaTxLib.LegacyMetaTransaction memory m) internal pure returns (MetaTxLib.MetaTransfer memory) {
-        return MetaTxLib.MetaTransfer({from: m.from, to: m.to, value: m.value, entryRef: 0, batch: m.batch,
-            nonce: m.nonce, validUntil: m.validUntil, mode: m.mode, relayer: m.relayer, fee: m.fee,
-            feeRecipient: m.feeRecipient});
-    }
-
     function _sigT(address t, MetaTxLib.MetaTransfer memory x) internal view returns (bytes memory) {
         (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, IERC20MetaTx(t).mtxTransferDigest(x));
         return abi.encodePacked(r, s, v);
@@ -139,8 +130,7 @@ contract MetaTxGasV2Test is Test {
 
     function _cool(address t) internal {
         vm.cool(t);
-        if (t != address(v1)) vm.cool(MetaTokenBase(t).implementation());
-        else vm.cool(v1.implementation());
+        vm.cool(MetaTokenBase(t).implementation());
         vm.cool(signer);
         vm.cool(relayer);
         vm.cool(recipient);
@@ -151,10 +141,9 @@ contract MetaTxGasV2Test is Test {
 
     /// Mỗi lần đo bắt đầu từ CÙNG một snapshot (kể cả tập địa chỉ/slot đã warm), nên thứ tự đo không làm lệch:
     /// một tài khoản dùng chung mà `vm.cool` không làm lạnh được làm lần đo thứ hai rẻ hơn ~2 500 nếu không có
-    /// snapshot. Mọi calldata (và chữ ký, vốn gọi `metaTxDigest`) dựng TRƯỚC `_snap()`; id snapshot là biến cục bộ
+    /// snapshot. Mọi calldata (và chữ ký, vốn gọi `mtxTransferDigest`) dựng TRƯỚC `_snap()`; id snapshot là biến cục bộ
     /// vì `revertToState` hoàn lại cả storage của chính hợp đồng test.
     function _snap() internal returns (uint256) {
-        _cool(address(v1));
         _cool(address(v2));
         _cool(address(v2b));
         _cool(address(v2c));
@@ -170,106 +159,80 @@ contract MetaTxGasV2Test is Test {
         assertTrue(ok);
     }
 
-    function _cdExec(address t, MetaTxLib.LegacyMetaTransaction memory m) internal view returns (bytes memory) {
-        return abi.encodeCall(IERC20MetaTxV1.executeMetaTransaction, (m, _sig(t, m)));
-    }
-
-    function _exec(address t, MetaTxLib.LegacyMetaTransaction memory m) internal {
-        vm.prank(relayer);
-        (bool ok,) = t.call(_cdExec(t, m));
-        assertTrue(ok);
-    }
-
-    function _row(string memory label, MetaTxLib.LegacyMetaTransaction memory m) internal returns (uint256 g1, uint256 g2) {
-        bytes memory c1 = _cdExec(address(v1), m);
-        bytes memory c2 = _cdT(address(v2), _x(m));
-        uint256 s = _snap();
-        g1 = _measure(address(v1), c1);
-        vm.revertToState(s);
+    function _row(string memory label, MetaTxLib.MetaTransfer memory x, uint256 g1) internal returns (uint256 g2) {
+        bytes memory c2 = _cdT(address(v2), x);
+        _snap();
         g2 = _measure(address(v2), c2);
         console.log(label);
-        console.log("   v1 / v2 / delta", g1, g2, g2 > g1 ? g2 - g1 : 0);
+        console.log("   v1 (frozen) / v2 / delta", g1, g2, g2 > g1 ? g2 - g1 : 0);
         assertLe(g2, g1 + BUDGET, label);
     }
 
-    function test_gasA_warmBatchNoFee() public { _row("A warm batch, NONE", _mt(0, WARM, 1, 0, address(0))); }
+    function test_gasA_warmBatchNoFee() public { _row("A warm batch, NONE", _mt(0, WARM, 1, 0, address(0)), V1_A); }
 
-    function test_gasB_coldBatchNoFee() public { _row("B cold batch, NONE", _mt(0, COLD, 0, 0, address(0))); }
+    function test_gasB_coldBatchNoFee() public { _row("B cold batch, NONE", _mt(0, COLD, 0, 0, address(0)), V1_B); }
 
     function test_gasC_warmFixedFee() public {
-        _row("C warm batch, FIXED fee", _mt(MetaTxLib.MODE_FEE_FIXED, WARM, 1, 0.001 ether, relayer));
+        _row("C warm batch, FIXED fee", _mt(MetaTxLib.MODE_FEE_FIXED, WARM, 1, 0.001 ether, relayer), V1_C);
     }
 
     function test_gasD_warmPercentFee() public {
-        _row("D warm batch, PERCENT fee", _mt(MetaTxLib.MODE_FEE_PERCENT, WARM, 1, 5_000, relayer));
+        _row("D warm batch, PERCENT fee", _mt(MetaTxLib.MODE_FEE_PERCENT, WARM, 1, 5_000, relayer), V1_D);
     }
 
     function test_gasE_warmFixedRestricted() public {
         _row("E warm batch, FIXED+restrict", _mt(MetaTxLib.MODE_FEE_FIXED | MetaTxLib.MODE_RESTRICT_RELAYER
-            | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, WARM, 1, 0.001 ether, feeTaker));
+            | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, WARM, 1, 0.001 ether, feeTaker), V1_E);
     }
 
     function test_gasF_newRecipient() public {
-        MetaTxLib.LegacyMetaTransaction memory m = _mt(0, WARM, 1, 0, address(0));
-        m.to = address(0xD00D);
-        _row("F warm batch, new recipient", m);
+        MetaTxLib.MetaTransfer memory x = _mt(0, WARM, 1, 0, address(0));
+        x.to = address(0xD00D);
+        _row("F warm batch, new recipient", x, V1_F);
     }
 
     function test_gasG_erc1271() public {
-        MetaTxLib.LegacyMetaTransaction memory m = _mt(0, COLD, 0, 0, address(0));
-        m.from = address(acct);
-        bytes memory cd = abi.encodeCall(IERC20MetaTxV1.executeMetaTransaction, (m, hex"deadbeef"));
-        bytes memory c2 = abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (_x(m), hex"deadbeef"));
-        uint256 s = _snap();
-        uint256 g1 = _measure(address(v1), cd);
-        vm.revertToState(s);
+        MetaTxLib.MetaTransfer memory x = _mt(0, COLD, 0, 0, address(0));
+        x.from = address(acct);
+        bytes memory c2 = abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, hex"deadbeef"));
+        _snap();
         uint256 g2 = _measure(address(v2), c2);
-        console.log("G cold batch, ERC-1271  v1 / v2", g1, g2);
-        assertLe(g2, g1 + BUDGET);
+        console.log("G cold batch, ERC-1271  v1 (frozen) / v2", V1_G, g2);
+        assertLe(g2, V1_G + BUDGET);
     }
 
     function test_gasP_payOpColdLane() public {
-        MetaTxLib.LegacyMetaTransaction memory m = _mt(MetaTxLib.MODE_RESTRICT_RELAYER, 0, 0, 0, address(0));
+        MetaTxLib.MetaTransfer memory x = _mt(MetaTxLib.MODE_RESTRICT_RELAYER, 0, 0, 0, address(0));
         bytes32 payId = keccak256("inv");
-        m.data = abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), payId);
-        m.batch = v2.payLane(payId);
-        MetaTxLib.MetaTransfer memory x = _x(m);
         x.entryRef = payId;
-        bytes memory c1 = _cdExec(address(v1), m);
+        x.batch = v2.payLane(payId);
         bytes memory c2 = _cdT(address(v2), x);
-        bytes memory cn = _named(v2.mtxPay.selector, abi.encode(signer, recipient, 1 ether, payId, m.validUntil,
-            m.mode, relayer, 0, address(0)), _sigT(address(v2), x));
+        bytes memory cn = _named(v2.mtxPay.selector, abi.encode(signer, recipient, 1 ether, payId, x.validUntil,
+            x.mode, relayer, 0, address(0)), _sigT(address(v2), x));
         uint256 s = _snap();
-        uint256 g1 = _measure(address(v1), c1);
-        vm.revertToState(s);
         uint256 g2 = _measure(address(v2), c2);
         vm.revertToState(s);
         uint256 gn = _measure(address(v2), cn);
-        console.log("P pay, fresh lane  v1 op / v2 mtxExecuteTransfer / mtxPay", g1, g2, gn);
-        assertLe(g2, g1 + BUDGET);
+        console.log("P pay, fresh lane  v1 op (frozen) / v2 mtxExecuteTransfer / mtxPay", V1_P, g2, gn);
+        assertLe(g2, V1_P + BUDGET);
         // no longer holds on `ERC20MetaTx` (mtxPay ≈ +2.6k over mtxExecuteTransfer on a fresh lane: the PAYABLE gate's cold SLOAD): logged, not asserted
         emit log_named_uint("P mtxPay", gn);
         emit log_named_uint("P mtxExecuteTransfer", g2);
     }
 
     function test_gasH_cancel() public {
-        uint256 s = _snap();
+        _snap();
         vm.prank(signer);
         uint256 g0 = gasleft();
-        v1.cancelMetaNonce(99);
-        uint256 g1 = g0 - gasleft();
-        vm.revertToState(s);
-        vm.prank(signer);
-        g0 = gasleft();
         v2.cancelNonce(99);
         uint256 g2 = g0 - gasleft();
-        console.log("H cancel (cold)  v1 cancelMetaNonce / v2 cancelNonce", g1, g2); // v2 adds the event + guard
+        console.log("H cancel (cold)  v1 cancelMetaNonce (frozen) / v2 cancelNonce", V1_H, g2); // v2 adds the event + guard
     }
 
     // ------------------------------------------------------------------ named vs generic (v2)
 
     function test_gasNamedTransferVersusGeneric_logOnly() public {
-        MetaTxLib.MetaTransfer memory x = _x(_mt(MetaTxLib.MODE_RESTRICT_RELAYER, WARM, 1, 0, address(0)));
+        MetaTxLib.MetaTransfer memory x = _mt(MetaTxLib.MODE_RESTRICT_RELAYER, WARM, 1, 0, address(0));
         bytes memory cg = _cdT(address(v2), x);
         bytes memory cn = _named(v2.mtxTransfer.selector, abi.encode(signer, recipient, 1 ether, WARM, 1,
             x.validUntil, x.mode, relayer), _sigT(address(v2), x));
@@ -286,7 +249,7 @@ contract MetaTxGasV2Test is Test {
 
     function test_gasNamedTransferWithFeeVersusGeneric_logOnly() public {
         uint32 mode = MetaTxLib.MODE_FEE_PERCENT | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
-        MetaTxLib.MetaTransfer memory x = _x(_mt(mode, WARM, 1, 5_000, feeTaker));
+        MetaTxLib.MetaTransfer memory x = _mt(mode, WARM, 1, 5_000, feeTaker);
         bytes memory cg = _cdT(address(v2), x);
         bytes memory cn = _named(v2.mtxTransferWithFee.selector, abi.encode(signer, recipient, 1 ether, WARM, 1,
             x.validUntil, mode, relayer, 5_000, feeTaker), _sigT(address(v2), x));
@@ -304,7 +267,7 @@ contract MetaTxGasV2Test is Test {
         MetaTxLib.MetaTransfer[] memory xs = new MetaTxLib.MetaTransfer[](3);
         bytes[] memory ss = new bytes[](3);
         for (uint256 i; i < 3; ++i) {
-            xs[i] = _x(_mt(MetaTxLib.MODE_RESTRICT_RELAYER, 10 + i, 0, 0, address(0)));
+            xs[i] = _mt(MetaTxLib.MODE_RESTRICT_RELAYER, 10 + i, 0, 0, address(0));
             ss[i] = _sigT(address(v2), xs[i]);
         }
         bytes memory cd = abi.encodeCall(v2.mtxBatchTransfer, (xs, ss));
@@ -344,7 +307,7 @@ contract MetaTxGasV2Test is Test {
     }
 
     function test_gasCalldata() public view {
-        MetaTxLib.MetaTransfer memory x = _x(_mt(MetaTxLib.MODE_RESTRICT_RELAYER, WARM, 1, 0, address(0)));
+        MetaTxLib.MetaTransfer memory x = _mt(MetaTxLib.MODE_RESTRICT_RELAYER, WARM, 1, 0, address(0));
         bytes memory s = _sigT(address(v2), x);
         _cd("I calldata mtxExecuteTransfer", abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, s)));
         _cd("I calldata mtxTransfer", _named(v2.mtxTransfer.selector, abi.encode(signer, recipient, 1 ether, WARM, 1,
``````


### Task 7: Docs, TODO, HANDOFF

Statuses move with the code (N18): the node pages (job-api, gateway, submit-lanes, dex-venue, store, mesh, README),
`networks/evm.md` and `networks/hedera.md`, the client pages, `contracts/metatx.md` and `contracts/dex.md` (their v1
restatements shrink to one paragraph each), `contracts/token-wrappers.md`, `architecture.md`, the two READMEs; TODO
(P5 row done, MT-1/MT-3/the backup items closed, MT-8/MT-9 built parts and what stays open, P1b note (c), the bamboo-dms
P5 item) and HANDOFF (P5 section); `dropped-artifacts.tsv` rows for every load-bearing token the shrink removed.

**Files:** modify `README.md`, `TODO.md`, `HANDOFF.md`, `smartcontracts/evm/README.md`, `smartcontracts/evm/legacy/README.md`,
`docs/architecture.md`, `docs/clients/{app,signers-clientkeys}.md`, `docs/contracts/{dex,metatx,token-wrappers}.md`,
`docs/networks/{evm,hedera}.md`, `docs/node/{README,dex-venue,gateway,job-api,mesh,store,submit-lanes}.md`,
`docs/history/dropped-artifacts.tsv`.

- [ ] **Step 1: Apply the diff below.**
- [ ] **Step 2: Checks.** `python3 scripts/docs_check.py check` — 0 errors (the one warning, `token-wrappers.md` over its
  budget, is `main`'s; the page shrinks by 2 lines); `python3 scripts/docs_check.py facts check` — 0 misses; over-budget
  pages net ≤ 0: `contracts/metatx.md` −36, `contracts/dex.md` −35 (its budget warning on `main` goes away), `contracts/token-wrappers.md` −2, `networks/hedera.md` −2, `node/README.md` 0.
- [ ] **Step 3: Commit** `P5 T7: docs, TODO, HANDOFF for the node, clientkeys and encoders on the new ABI; v1 line in legacy/p5`.

``````diff
diff --git a/HANDOFF.md b/HANDOFF.md
index 6542ed6..6a25d78 100644
--- a/HANDOFF.md
+++ b/HANDOFF.md
@@ -1,5 +1,36 @@
 # HANDOFF — scaas
 
+## Session 2026-10-11 (P5)
+
+**State:** P5 on branch `p5-node-abi`, merge pending the final review. Plan `docs/superpowers/plans/2026-10-11-p5-node-clients-new-abi.md`.
+844 forge tests (1001 + `DexKat` − 158 v1 tests moved to `legacy/p5/`); size gate 0 errors; `scaas-node` lib 254, mesh vectors + fuzz, clippy clean; e2e 4/4 and e2e_hedera 1/1; clientkeys 60 (58 pass, 2 skipped); mutation probe 39/39 killed.
+
+**Built:** `scaas-node` on the new tree: `src/abi.rs` (`MetaTransaction`, `MetaTransfer`, `TradeOrder`, `Leg`, `DexOrder`,
+`Settlement`, `IToken`, `ISCaaSDex`, `IMandateWallet` errors), `src/metatx.rs` (`Mtx { Call, Transfer }`, salted
+`Domain`, wire forms with `struct`), `src/guard.rs` (call table with the P4 rows, `chainUid()` binding, selector tables
+from `mtxSelectors()`, `mtxSettle` gas by simulation, ERC-1271 floor 432,349, `already_invalidated`), `src/dex.rs` and
+`src/dex/venue.rs` on the `SCaaSDex` clone (`TradeOrder`/`DexOrder`, `mtxSettle`, outside legs, cancels where the order
+lives, `SigCheckGasStarved` split, empty `MatchFailed` = `out_of_gas`), the mesh EVM body with `salt`, `Chain::uid()`
+(block 0 or `chain_uid`; a wrong pin refuses the lane); clientkeys `checkPayment` on `MetaTransfer` with `chainUid`,
+`checkCall`, `tradeOrderTypedData`, `orderCancelTypedData`, `checkTradeOrder`; KATs with relayed calldata and the new
+`dex_order_kat.json`, `hedera_kat.json` v3; deploy: two demo tokens from `OpenFactory` (`demo_token`, `demo_token_2`),
+v1 keys gone. The v1 line (`MetaToken`, `HederaMetaToken`, `OpenFactoryV1`, `MetaTxDex`, `SCaaSDexV1`, their tests and
+vectors, the Hedera smoke) is in `smartcontracts/evm/legacy/p5/`; the node's and clientkeys' v1 encoders in their
+`legacy/p5/` (not built).
+
+**Rulings N1–N18 (plan header).** **N1** `struct` absent = `transfer`, unknown fields refused; **N2** `chain_uid` from block 0
+or config, a mismatch stops the lane; **N3** call table only for built contracts, `mtxExecuteAsOwner` under the wallet rule,
+token entries as `metatx` jobs; **N5** `mtxSettle` gas ×1.5 until every settlement settles, a whole-call revert is final;
+**N6** `MinNonceNotIncreasing` = consumed `already_invalidated`; **N7** venue rules (one settlement per taker, crossing
+remainder dropped, makers restored first, `ESCROW` refused, fee rate by role); **N13** deploy without v1; **N14** v1 to
+`legacy/p5/`, `MetaTxGasV2.t` against frozen v1 numbers.
+
+**Not done / next:** bamboo-dms follows before the P5 node reaches a chain Odoo uses (TODO P5: jobs with `struct` and
+salted digests, KAT repoints, DEX book shapes, events, `already_invalidated`, mesh vectors, deploy keys, the portal
+bundle); deferred (TODO MT-8): batching and the per-selector breaker (NODE-LANE-11, -25), TradeEngine (P7),
+NODE-IDX-06 `repeat_of`, `ua_metatx`, client Zether encoders after P3b, the per-poll market re-check; open questions in
+the plan.
+
 ## Session 2026-10-11 (P4)
 
 **State:** P4 on branch `p4-accounts`, merge pending the final review. Plan `docs/superpowers/plans/2026-10-11-p4-accounts-mandates.md`.
diff --git a/README.md b/README.md
index d59211b..9e54d75 100644
--- a/README.md
+++ b/README.md
@@ -272,11 +272,11 @@ heavy logic sits in external libraries ([CTR-TOK-21](docs/contracts/token-wrappe
 
 | Area | Contracts | Built on | Status | Read |
 |---|---|---|---|---|
-| Factory | `OpenFactory` (one factory) | EIP-1167 clones at CREATE2 addresses: shared code, separate data ([section 4](#shared-code)); the version catalogue | BUILT as `OpenFactory` (`createToken`; kinds `NORMAL`, `WRAPPED`, and `NORMAL_ZETHER`, `WRAPPED_ZETHER` on dev chains, P3) and the v1 line `OpenFactoryV1` | [token-wrappers](docs/contracts/token-wrappers.md) |
+| Factory | `OpenFactory` (one factory) | EIP-1167 clones at CREATE2 addresses: shared code, separate data ([section 4](#shared-code)); the version catalogue | BUILT as `OpenFactory` (`createToken`; kinds `NORMAL`, `WRAPPED`, and `NORMAL_ZETHER`, `WRAPPED_ZETHER` on dev chains, P3); the v1 line `OpenFactoryV1` is in `legacy/p5/` (P5) | [token-wrappers](docs/contracts/token-wrappers.md) |
 | Gasless contracts | `MetaTxBase` (any SCaaS contract) → `ERC20MetaTx` (every token) → `MetaTokenBase` | `EIP712`; `mtxExecute` runs a signed `MetaTransaction` as a self-call on a selector allowlist; tokens add `ERC20` + `IERC20MetaTx` and the typed `MetaTransfer` ([CTR-MTX-22](docs/contracts/metatx.md#CTR-MTX-22), [CTR-MTX-23](docs/contracts/metatx.md#CTR-MTX-23)) | BUILT (P1a–P1c): `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; the older v1 line remains until the node and clientkeys move (P5) | [metatx](docs/contracts/metatx.md) |
 | Payments | a signed `MetaTransfer` with an `entryRef` (`mtxPay`), or `IERC20Payment.payWithFee`; both emit `PaymentSettled` | `IERC20MetaTx` | BUILT: `MetaTransfer` and `mtxPay` on `MetaTokenBase`; the v1 line keeps a `pay(bytes32)` data shape | [metatx](docs/contracts/metatx.md) |
 | Token kinds | four kinds by code: `NormalToken` (`NORMAL`), `WrappedToken` (`WRAPPED`, 1–8 legs, the native coin allowed), `NormalZetherToken`, `WrappedZetherToken` (the two `*_ZETHER` kinds); `*_PQZ` reserved. Features by flags fixed at creation: payable, mint, burn, adjustable rate, wrap-disable, freeze, force, pause, allowlist ([CTR-TOK-21](docs/contracts/token-wrappers.md#CTR-TOK-21)) | `MetaTokenBase` | `NORMAL` and `WRAPPED` BUILT (P1c–P1d) with `AdminLib`, `WrappedLib`, `HederaLib` (`WrappedToken` still over EIP-170); `*_ZETHER` kinds with `ZetherLib` BUILT, unaudited (P3; over EIP-170 too) | [token-wrappers](docs/contracts/token-wrappers.md) |
-| Tradable tokens | `mtxTrade`: the token pulls a signed `TradeOrder` into the DEX named in it | `IERC20MetaTx` | SPECIFIED (`TradeLib`, P2; today: the `trade` op and the legacy `MetaTxDex`, both to be removed) | [metatx](docs/contracts/metatx.md), [legacy DEX](docs/contracts/dex.md#legacy-metatxdex) |
+| Tradable tokens | `mtxTrade`: the token pulls a signed `TradeOrder` into the DEX named in it | `IERC20MetaTx` | BUILT (`TradeLib`, P2; the `trade` op and the legacy `MetaTxDex` are in `legacy/p5/`, P5) | [metatx](docs/contracts/metatx.md), [legacy DEX](docs/contracts/dex.md#legacy-metatxdex) |
 | DEX | `SCaaSDex`, `DexPuller` | `EIP712` + `ReentrancyGuardTransient`; one taker against many makers per call on two paths, no maker allowance; `mtxExchange` fills the same orders against AMMs (Uniswap v2/v3), multi-hop or in a cycle, surplus to the signers ([CTR-DEX-20](docs/contracts/dex.md#CTR-DEX-20)) | BUILT (P2c: the exchange path on the new `SCaaSDex`) | [dex](docs/contracts/dex.md) |
 | Mandates | `MandateWallet` | `MetaTxBase` + `IERC1271` | BUILT (on `MetaTxBase`, P4) | [mandates](docs/contracts/mandates.md) |
 | Smart account (optional) | `SmartKeyAccount`, `SmartKeyAccountFactory` | `MetaTxBase` + `IERC1271`; P-256 passkeys; signs its own calls as itself ([CTR-ACC-10](docs/contracts/accounts.md#CTR-ACC-10)) | BUILT (on `MetaTxBase`, P4) | [accounts](docs/contracts/accounts.md#subjectaccount) |
diff --git a/TODO.md b/TODO.md
index c77dfc5..efd232d 100644
--- a/TODO.md
+++ b/TODO.md
@@ -17,7 +17,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 | P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, merged `6a5c6b0`); **P2b-1** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` for SCaaS legs (done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2b-2** outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done, merged `7049c78`; `checkOrder` not built, H7); **P2c** exchange path `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly` (done, merged `d85fc8b`) | MT-5 |
 | P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; `ZetherToken` to `legacy/p3/` (owner: backup, not delete) (done, merged `dc9d219`; P3b modes pending) | MT-6 |
 | P4 | `MandateWallet`, `SmartKeyAccount` (rename: EVM, Solana, Soroban) on `MetaTxBase`; the typed-struct line to `legacy/p4/` (done, merged `ebacaac`) | MT-7 (+ rename in NM-*) |
-| P5 | Node, clientkeys, encoders for the new ABI | MT-8, MT-9 |
+| P5 | Node, clientkeys, encoders for the new ABI; the v1 line to `legacy/p5/` (done; plan `docs/superpowers/plans/2026-10-11-p5-node-clients-new-abi.md`) | MT-8, MT-9 |
 | P6 | PQ Zether after P5 (owner 2026-10-11): the E-S0…E-S8 stream ([pq-zero-knowledge.md](docs/contracts/pq-zero-knowledge.md)) on the finished token tree (`PqzToken` with CTR-PQZ-23/24 modes); PQ signatures as compatible as possible with the Ethereum drafts, both directions: ML-DSA ([EIP-8051](https://eips.ethereum.org/EIPS/eip-8051), [EIP-8355](https://eips.ethereum.org/EIPS/eip-8355): empty FIPS 204 context with domain separation in the message, the EIP key and message encodings incl. the expanded key) and Falcon/FN-DSA ([EIP-8052](https://eips.ethereum.org/EIPS/eip-8052): its hash variant and encoding); precompiles found by probe at the EIP addresses, the 7622 addresses moved out of the EIP-1352 range; see [pq-eips-vs-scaas.md](docs/research/pq-eips-vs-scaas.md) Q1–Q3, Q6; owner 2026-10-11 ([CTR-UA-23](docs/contracts/accounts.md#CTR-UA-23)): ML-DSA with the empty context and the kind tag in the message (`pq_msg = keccak256(TAG(kind) ‖ ua_msg)`), vectors regenerated; new kind `slhdsa128s` (0x0133, SLH-DSA-SHA2-128s, FIPS 205) with a gas-measurement gate before any public chain enables it | UA PQ kinds, E-S* |
 
 **P1 start checklist (owner decisions 2026-10-08):**
@@ -30,13 +30,13 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
       `ERC1776Dex.mtxTrade`) and the `OP_TRADE` legs of `MetaToken`/`MetaTokenBase`/`MetaTxDex`.
 
 **P1 — MT-1…MT-4**
-- P1 is split into five plans, written one at a time: **P1a** (MetaTxBase, SigCheck, SaltedEIP712, tag + legacy) — **done 2026-10-09**, merged `1d51d22` (712 tests); plan `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md`; **P1b** ERC20MetaTx — **done 2026-10-10** merged `fb2a234` (758 tests); **P1c** MetaTokenBase + AdminLib/HederaLib + kind NORMAL (no `PayLib`, C3) — **done 2026-10-10**, merged `3a43c2e` (792 tests); **P1d** WrappedLib + WrappedToken (1–8 legs, native leg, roles) — **done 2026-10-11**, merged `d03d894` (814 tests, e2e 4/4 + e2e_hedera 1/1); plan `docs/superpowers/plans/2026-10-11-p1d-underlyingtoken.md`; **P1e** `OpenFactory` (`createToken`/`TokenConfig`), CREATE2 deployer + `chainUid()` gate, size gate (ratchet), v1 renamed `…V1`, factory v2 backed up — **done 2026-10-11**, merged `e433bf5` (819 tests, e2e 4/4 + e2e_hedera 1/1); plan `docs/superpowers/plans/2026-10-11-p1e-openfactory.md`. P1 is complete except the partial items MT-1 (v1 line kept as `…V1`), MT-3 (v1 approve), MT-4 (other domains) and the parked items below.
+- P1 is split into five plans, written one at a time: **P1a** (MetaTxBase, SigCheck, SaltedEIP712, tag + legacy) — **done 2026-10-09**, merged `1d51d22` (712 tests); plan `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md`; **P1b** ERC20MetaTx — **done 2026-10-10** merged `fb2a234` (758 tests); **P1c** MetaTokenBase + AdminLib/HederaLib + kind NORMAL (no `PayLib`, C3) — **done 2026-10-10**, merged `3a43c2e` (792 tests); **P1d** WrappedLib + WrappedToken (1–8 legs, native leg, roles) — **done 2026-10-11**, merged `d03d894` (814 tests, e2e 4/4 + e2e_hedera 1/1); plan `docs/superpowers/plans/2026-10-11-p1d-underlyingtoken.md`; **P1e** `OpenFactory` (`createToken`/`TokenConfig`), CREATE2 deployer + `chainUid()` gate, size gate (ratchet), v1 renamed `…V1`, factory v2 backed up — **done 2026-10-11**, merged `e433bf5` (819 tests, e2e 4/4 + e2e_hedera 1/1); plan `docs/superpowers/plans/2026-10-11-p1e-openfactory.md`. P1 is complete except the partial item MT-4 (other domains) and the parked items below (MT-1/MT-3's v1 part closed in P5: the v1 line is in `legacy/p5/`).
 - Asset-suite wording follow-up (P1c final re-review): `asset-suite.md` ~791/793/794/854/906 still say "minter renounced" as the precondition for bond redemption and splits; since P1c the rule is "`MINTABLE` disabled (`disableFeature`)" — `renounceRole` alone leaves the flag set and still yields `MinterLive` (fails closed). Reword when the asset-suite stream starts.
-- P1b notes (2026-10-10: all done in P1b except (c), a P5 node item, and (g), deliberately not done; (d) done on bamboo-dms branch `scaas-metatx-v1-kat`, owner merges): (a) `MetaTxBase` alone is ≈ 9.4 KB on the mock — watch the 20,480 B token budget; (b) pin 'every allowlisted function is nonReentrant' without the mock's `poke` forwarder — resolved in P1a final review: `_selfCall` requires ticket 2; (c) relayer gas estimate for SubjectAccount/SmartKeyAccount signers must cover 400k·64/63 + 5k for the ERC-1271 call (P5 node); (d) bamboo-dms `dms_blockchain/tests/test_eip712.py:14` must be repointed to `metatx_v1_kat.json` (other repo). (e) `ERC20MetaTx` (git mv of `MetaTxCore`) sits on `MetaTxBase`: drop `MetaTxCore`'s own `nonReentrant` and `_metaNonce`, declare `_msgSender() override(Context, MetaTxBase)`, `MetaTransfer` path uses `_checkEnvelope` + `_useNonce` (watch the order of the three adjacent uint256 args `batch, nonce, validUntil`); (f) each token re-pins `mtxSelectors()` == `_mtxRule`, and keeps the "no `mtx…` in the allowlist" test; (g) optional: fee checks before the call (`_checkFee` in step 3) so a doomed tx is cheap; a dedicated error for an unguarded allowlisted target (today `Reentrancy()`); (h) `eip712Domain` drop `virtual`; v1 KAT writer `MetaTxKat.t.sol` gets the `WRITE_KAT` guard.
+- P1b notes (2026-10-10: all done in P1b except (c), done in P5 (the node's ERC-1271 gas floor 432,349), and (g), deliberately not done; (d) done on bamboo-dms branch `scaas-metatx-v1-kat`, owner merges): (a) `MetaTxBase` alone is ≈ 9.4 KB on the mock — watch the 20,480 B token budget; (b) pin 'every allowlisted function is nonReentrant' without the mock's `poke` forwarder — resolved in P1a final review: `_selfCall` requires ticket 2; (c) relayer gas estimate for SubjectAccount/SmartKeyAccount signers must cover 400k·64/63 + 5k for the ERC-1271 call (P5 node); (d) bamboo-dms `dms_blockchain/tests/test_eip712.py:14` must be repointed to `metatx_v1_kat.json` (other repo; P5 moved it to `legacy/p5/test/vectors/`, see the bamboo-dms item under P5). (e) `ERC20MetaTx` (git mv of `MetaTxCore`) sits on `MetaTxBase`: drop `MetaTxCore`'s own `nonReentrant` and `_metaNonce`, declare `_msgSender() override(Context, MetaTxBase)`, `MetaTransfer` path uses `_checkEnvelope` + `_useNonce` (watch the order of the three adjacent uint256 args `batch, nonce, validUntil`); (f) each token re-pins `mtxSelectors()` == `_mtxRule`, and keeps the "no `mtx…` in the allowlist" test; (g) optional: fee checks before the call (`_checkFee` in step 3) so a doomed tx is cheap; a dedicated error for an unguarded allowlisted target (today `Reentrancy()`); (h) `eip712Domain` drop `virtual`; v1 KAT writer `MetaTxKat.t.sol` gets the `WRITE_KAT` guard.
 - P1c notes (from the P1b reviews, 2026-10-10): (a) the typed path's "cannot fail after step 3" and `mtxPayReceiverFee` step 5 hold only while `_update` refuses nothing beyond `to == this`: any P1c pause/freeze/feature refusal added to `_update` must be mirrored in `_checkTransfer` (and checked before the receiver-fee transfer); (b) `_chargeFee` re-derives the fee class from `_mtxRule`, so rules must stay constant per selector (hardened in P1b: an ABSOLUTE+FIXED fee is taken as is); (c) Multi `_mtxRule` falls back to `MetaTxBase._mtxRule`, so rules P1c adds in `ERC20MetaTx`/`MetaTokenBase` are dropped on Multi (moot after P1d; otherwise switch it to `MetaTokenBase._mtxRule`); (d) `HederaAccountAuth.sol:29` `asView` safety comment names `executeMetaTransaction` as the sole call site: there are now many non-view call sites (all `nonReentrant`, non-static frames), still safe; repoint the comment in P1c (HederaLib); (e) deferred test gaps still open: Task 3 — `FeePolicy.validateRecipient` is unreachable on both paths (the resolved recipient is never 0; delete or pin), no success-path test of a relayer-filled third-party `feeRecipient` on the typed path (only the `== to` refusal, `test/v2/Base.t.sol`); Task 4 — unwrap: no raw `ERC20InsufficientBalance`-from-`_burn` case when the reserve suffices, no dirty-address-word case; Task 5 — no SmartKeyAccount-clone (400k) payee test, no single-field tamper tests (`fee`/`feeRecipient`/`rfValidUntil`), no invalid-fee-nibble shape case, no RP4 assertions after a failed co-signature. Task 6's gaps were closed in the P1b final fix wave.
 - P1c notes dispositions (2026-10-10): (a) no `_update` refusal was added in P1c (flags 5–8 are refused at init, C2): carry to the asset-suite stream; (b) unchanged; (c) done in P1d (`WrappedToken._mtxRule` falls back to `super._mtxRule`); (d) done (`HederaLib`, `asView` comment repointed); (e) open test gaps stay as listed.
 - Asset-suite stream, from the P1c final review (C2): issuer and compliance must be contract-only when flags 5–8 are built; roles are keyed by flag bit and `_grant` requires the role's own bit, which cannot express FORCE = issuer + compliance or one issuer shared by FREEZE/FORCE/PAUSE, so the stream must key roles by role id (issuer, compliance) or map bits; and any `_update` refusal (freeze/pause/allowlist) must be mirrored in `_checkTransfer` and before the receiver-fee transfer.
-- [~] **MT-1** (built through P1e: kinds on `TokenConfig`, `OpenFactory.createToken`; the v1 line is kept as `…V1` until P5 (the node's e2e deploys it), see the backup item under P5; owner: backup, not delete) Two bases: generic `MetaTxBase` (any SCaaS contract; `_chargeFee` refuses all but `NONE`, CTR-MTX-22) and
+- [~] **MT-1** (built through P1e: kinds on `TokenConfig`, `OpenFactory.createToken`; the v1 line moved to `smartcontracts/evm/legacy/p5/` in P5; owner: backup, not delete) Two bases: generic `MetaTxBase` (any SCaaS contract; `_chargeFee` refuses all but `NONE`, CTR-MTX-22) and
       the token base `ERC20MetaTx is MetaTxBase` (absorbs `MetaTxCore`) with `MetaTokenBase` on top; kinds `NORMAL` and
       `WRAPPED` (the native-coin leg, CTR-TOK-26) with `AdminLib`, `WrappedLib`, `HederaLib`, `SigCheck` (CTR-TOK-21…24); factory
       `createToken` (CTR-TOK-25). Delete what token-tree spec §8 deletes: `ERC20MetaTx`(v1), `MetaToken`, `HederaMetaToken`,
@@ -49,7 +49,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
       all-or-nothing; `_msgSender()` everywhere per the `msg.sender` inventory; lint/test that no token reads
       `msg.sender` directly except the allowed spots; UA path split into `UAMetaTransaction`/`UAMetaTransfer` +
       `uaExecuteTransfer`/`uaBatchTransfer` (CTR-UA-26); KATs `metatx_kat.json`, `metatransfer_kat.json`, v3 pair.
-- [ ] **MT-3** `approve` only by contracts (caller and spender) — built in P1b on the v2 line; open: v1 line (P5, E1); `mtxWrap` for a SCaaS underlying done in P2a (WrappedToken), inherited by `WrappedZetherToken` (P3); the approve rule holds on both Zether kinds (tested in P3).
+- [x] **MT-3** `approve` only by contracts (caller and spender) — built in P1b on the v2 line; the v1 line left the build in P5 (`legacy/p5/`); `mtxWrap` for a SCaaS underlying done in P2a (WrappedToken), inherited by `WrappedZetherToken` (P3); the approve rule holds on both Zether kinds (tested in P3).
 - [~] **MT-4** (built in P1e for tokens and the token factory: both deploy scripts on CREATE2, gate on `chainUid()`; open for the UA registry, UA F1; Zether digests done in P3, SmartKeyAccount and MandateWallet in P4) `salt = chain_uid` in every domain (implementation immutables; SmartKeyAccount, MandateWallet, SCaaSDex,
       UA registry, Zether digests); deploy scripts on a CREATE2 deployer; deploy gate checks `chainUid()`.
 
@@ -61,7 +61,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 
 **P2 — MT-5**
 - P2a (done, merged `6a5c6b0`): `TradeLib` (`scaas.trade`) and the trade entries on every token, `mtxWrap` + `NativeNotGasless` on `WrappedToken` (D1 closed; a native wrap by `mtxExecute(wrap(…))` still reverts `NativeValueMismatch(0, amount)`); 855 tests. Plan `docs/superpowers/plans/2026-10-11-p2a-trade-token-side.md`. Open for P2b/P2c: the DEX side below. **F4 (owner): `NormalToken` is 22,951 B, over its 20,480 B budget (ratchet baseline), `WrappedToken` 29,974 B: owner — code size is not a concern, the product waits for the Glamsterdam fork (larger code limit); the ratchet baseline records sizes.**
-- P2b-1 (done, merged `0510c7d`): `SCaaSDex` clone (`scaas.dex`, salted domain `SCaaS Dex`; MT-4 domain done for the new DEX), `OpenFactory` DEX catalogue and `createDex`/`isDex`/`dexVersionOf`, deploy key `dex_implementation`, built DEX kept as `SCaaSDexV1`; 891 tests. Plan `docs/superpowers/plans/2026-10-11-p2b1-scaasdex-clone.md`. P2b-2 built them except `checkOrder` (see P2b-2). P2c built `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly`. `SCaaSDexV1` moves to `legacy/` at P5 (owner: backup, not delete).
+- P2b-1 (done, merged `0510c7d`): `SCaaSDex` clone (`scaas.dex`, salted domain `SCaaS Dex`; MT-4 domain done for the new DEX), `OpenFactory` DEX catalogue and `createDex`/`isDex`/`dexVersionOf`, deploy key `dex_implementation`, built DEX kept as `SCaaSDexV1`; 891 tests. Plan `docs/superpowers/plans/2026-10-11-p2b1-scaasdex-clone.md`. P2b-2 built them except `checkOrder` (see P2b-2). P2c built `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly`. `SCaaSDexV1` moved to `legacy/p5/` in P5 (owner: backup, not delete).
 - P2b-2 (done, merged `7049c78`): outside legs (`DexOrder` in the DEX domain, `TradeLib` on the DEX's own `scaas.trade` state, `ESCROW` refused), `DexPuller` deployed by `initialize`, `mtxCancelOrders` / `mtxInvalidateNonces`, ERC-1271 cap by codehash (constructor takes the `SmartKeyAccount` implementation), `MatchFailed` reason capped at 256 bytes, `SigCheckGasStarved` reverts the whole `mtxSettle` (m8 closed), payouts by `SafeERC20`; 913 tests. Plan `docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. Open: `checkOrder` for the new DEX (not specified: dex.md §10 reads are the intake; with the node's P7 intake), the DEX invariant suite (§14). Size baseline raised by 9 B per token (`precheck` argument). Node P7: a batch reverting with `SigCheckGasStarved` is split and simulated per settlement, never retried whole with more gas (a party's `destination` that is a hook-token recipient can forge the selector; hook tokens are never listed). `mtxSettle` success is not monotonic in gas (a settlement can fail with an empty `MatchFailed` reason at a gas above a starved-revert window), so the node never trusts plain `eth_estimateGas`: it sizes gas from a simulation that requires every planned `ok[i]` true and reads an empty `MatchFailed` reason as out of gas (retry with more gas, never mark the order invalid). Limitation: no HIP-632 branch on DEX signatures, so a Hedera ED25519 account cannot sign a `DexOrder` or a DEX-side cancel (follow-up: `IS_HEDERA` in `SCaaSDex`).
 - P2c (done, merged `d85fc8b`): the exchange path on `SCaaSDex` — `mtxExchange` (interactions: never the DEX or the puller, never `mtxTrade`, data of at least 4 bytes), `mtxExchangeVia` (`IExchangeExecutor.exchangeCallback`), `setExchangeTarget` / `setListedOnly` and the `LISTED_POOLS` condition, `tokenKnown` (counted per listed market), the surplus to the signers by floor with the remainder to the last leg, `InsufficientOutput`, conservation over every snapshotted token, a pull check that refuses an inexact sell token, every `approve` interaction reset to 0, `increaseAllowance` and Permit2 `approve` refused (`ForbiddenSelector`, controller ruling, pending the owner); `ExchangeLegSettled`; 949 tests. Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`. Open: the fork test with real Uniswap bytecode (dex.md section 14), the DEX invariant suite, the node's TradeEngine (NODE-DEX-17/18, P7).
 - P2 notes (from P1c, P1d): (2) Named `mtxTransfer` is +9 execution gas over `mtxExecuteTransfer` (33,681 vs 33,672): the row is logged, not asserted; `mtxPay` on a fresh lane is +2.6 k (the `PAYABLE` gate's cold SLOAD, C3). (3) The asset suite's inline per-transfer admin check (CTR-TOK-24) also needs NORMAL bytes: it competes with the size debt in F4.
@@ -73,8 +73,8 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
       `setListedOnly` (CTR-DEX-03); tokens accept `receiveToken == this` and flag 4 (CTR-DEX-15).
 
 **P3 — MT-6**
-- P3 (done, merged `dc9d219`; P3b modes pending): `NormalZetherToken` / `WrappedZetherToken` (`ZetherLayer is MetaTokenBase`, logic in the external `ZetherLib`, `scaas.zether`), `ZetherStatements`, `zetherShield` from the public balance, `zetherWrapShield` / `zetherUnshieldUnwrap` on `WRAPPED_ZETHER` (nothing minted), relaying through `mtxExecute` with the envelope binding in the transient ticket (`MetaTxBase._envelopeBinding`), `chainUid` in every token-side digest and the 416-byte header, the Zether gate on `OpenFactory`, `DeployBase` registers kinds 2–3 on dev chains with `DEPLOY_ZETHER=1` (opt-in), the prover on the new header and ABI; the built `ZetherToken`, `ZetherMetaTx`, old `IZetherToken` and their tests in `smartcontracts/evm/legacy/p3/`; 977 tests. Plan `docs/superpowers/plans/2026-10-11-p3-zether-kinds.md`. Open: a real-passkey envelope test (CTR-ZTH-21), gas of `zetherWrapShield` / `zetherUnshieldUnwrap` (the zether.md gas tables are re-measured on the new kinds), the registry's `chainUid` (UA F1), client ABI (P5); disclosure questions for the disclosure review (plan header).
-- [ ] v1 line to backup (P5): `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1` (and `MetaToken`/`HederaMetaToken`/`MetaTxDex`) wait for the node and clientkeys (the e2e deploys them); the Zether part moved in P3 (E1; owner: backup, not delete).
+- P3 (done, merged `dc9d219`; P3b modes pending): `NormalZetherToken` / `WrappedZetherToken` (`ZetherLayer is MetaTokenBase`, logic in the external `ZetherLib`, `scaas.zether`), `ZetherStatements`, `zetherShield` from the public balance, `zetherWrapShield` / `zetherUnshieldUnwrap` on `WRAPPED_ZETHER` (nothing minted), relaying through `mtxExecute` with the envelope binding in the transient ticket (`MetaTxBase._envelopeBinding`), `chainUid` in every token-side digest and the 416-byte header, the Zether gate on `OpenFactory`, `DeployBase` registers kinds 2–3 on dev chains with `DEPLOY_ZETHER=1` (opt-in), the prover on the new header and ABI; the built `ZetherToken`, `ZetherMetaTx`, old `IZetherToken` and their tests in `smartcontracts/evm/legacy/p3/`; 977 tests. Plan `docs/superpowers/plans/2026-10-11-p3-zether-kinds.md`. Open: a real-passkey envelope test (CTR-ZTH-21), gas of `zetherWrapShield` / `zetherUnshieldUnwrap` (the zether.md gas tables are re-measured on the new kinds), the registry's `chainUid` (UA F1), client Zether encoders (after P3b; the node relays Zether calls opaquely, P5); disclosure questions for the disclosure review (plan header).
+- [x] v1 line to backup (P5): `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1`, `MetaToken`, `HederaMetaToken`, `MetaTxDex`, `SCaaSDexV1` and their tests in `smartcontracts/evm/legacy/p5/`; the Zether part moved in P3 (E1; owner: backup, not delete).
 - [ ] `mtxBatch` needs a not-batchable hook for PQZ selectors (`MtxNotBatchable(selector)`, pq-zero-knowledge.md CTR-PQZ-21): with `PqzToken` (no PQZ selector exists yet; P3 left the room: the binding hook takes a PQZ tag).
 - [~] **MT-6** Zether (done in P3: transient envelope binding, `zetherShield` from the public balance, `mtxWrap` inherited, the `zether*` renames, binding without `to`/`value`, prover `Header.chain_uid`, `HEADER_LEN` 416; open: `PqzToken` on the one base, PQZ selectors not batchable, CTR-PQZ-21, with the PQZ stream).
 - [ ] **P3b** Zether storage and auditor modes (owner 2026-10-11; spec: zether.md CTR-ZTH-30/38/42/48/49/50, pq-zero-knowledge.md CTR-PQZ-19/23/24, already written): `ConfidentialConfig.disclosureMode`/`auditorMode` + factory and `initialize` validation (`BadDisclosureMode`, `BadAuditorMode`); entry renames (`zetherTransfer` = mode default, `zetherTransferCompact`, `zetherTransferNoBundle` BUNDLE-only, `zetherTransferBundle` to legacy) and guards (`TransferEntryDisabled`, `AuditorRequired`); auditor modes NONE/FULL/OPTIONAL; `s` v2 with the 16-byte salt in payload and the 480-byte header (new `proofSystemId`); sender memo + `memoHash` and a recovery helper in the prover (seed + storage → openings); relay allowlist and selectors; vectors/KATs regenerated; gas re-measured (§19). PQZ: spec only.
@@ -86,15 +86,10 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 - [ ] Agent mandates (research `docs/research/node-ai-agents.md` row c, not accepted): several delegates per token, per-payee caps, a co-sign threshold, a gateway route for mandate payments — owner decision.
 
 **P5 — MT-8, MT-9**
-- [ ] v1 line to backup: once the node (`src/abi.rs` v1 struct, `executeMetaTransaction`, salt-less domain; e2e v1 `MetaToken` demo tokens) and clientkeys (`metatx_v1_kat.json`) are on the new ABI, move the v1 contracts and the v1 deploy path to `smartcontracts/evm/legacy/` (E1).
-- [ ] **MT-8** Node: `mtxInvalidateNonces` replay reverts `MinNonceNotIncreasing` (strictly increasing): the cancel job treats that revert as success; two `sol!` structs, `metatx`/`ua_metatx` jobs name their struct (`call` | `transfer`), selector tables for
-      every contract on `MetaTxBase` (NODE-JOB-20), call table names, breaker per `(from, selector)` (`MetaTransfer` =
-      `transfer`/`pay`), batching via `mtxBatchTransfer`/`mtxBatch` never mixed (NODE-LANE-11), `chainUid()` check
-      (NODE-GW-07), DEX venue `mtxSettle` (NODE-DEX-15/16), intake `allowance(from, puller)`, TradeEngine with
-      `trade_engine.*` config and `/v1/dex/exchanges/{ref}` (NODE-DEX-17/18), NODE-IDX-06 `repeat_of`.
-- [ ] **MT-9** clientkeys/app and the reference ERP's `lib/eip712.py`: both structs (`MetaTransfer` typed in wallets,
-      `MetaTransaction` decoded via `mtxSelectors()`), `domain.salt`, refuse an unlisted `dex`, no EOA approve, wrap by
-      signature (CLI-SGN-05, CLI-SGN-33…36); `SmartKeyAccount`/mandate digests as `MetaTransaction`s; vectors/KATs regenerated.
+- [x] v1 line to backup: the node and clientkeys are on the new ABI; the v1 contracts, tests, KATs and deploy path are in `smartcontracts/evm/legacy/p5/`, the node's and clientkeys' v1 encoders in `scaas-node/legacy/p5/` and `clients/clientkeys/legacy/p5/` (E1).
+- [~] **MT-8** Node (P5 built): two `sol!` structs, `metatx` jobs name their struct (`call` | `transfer`, absent = `transfer`), the call table and the selector tables from `mtxSelectors()` (NODE-JOB-19/20), `chainUid()` check (NODE-GW-07), `MinNonceNotIncreasing` on an invalidation = consumed `already_invalidated`, ERC-1271 gas floor (P1b (c)), DEX venue on the clone `mtxSettle` with outside legs and DEX-side cancels (NODE-DEX-15/16), intake `allowance(from, puller)`. Open: breaker per `(from, selector)` and batching via `mtxBatchTransfer`/`mtxBatch` (NODE-LANE-11, NODE-LANE-25), TradeEngine with `trade_engine.*` and `/v1/dex/exchanges/{ref}` (NODE-DEX-17/18, P7), NODE-IDX-06 `repeat_of`, `ua_metatx` (UA F1), the per-poll venue check (NODE-DEX-08).
+- [~] **MT-9** clientkeys (P5 built): `MetaTransfer` typed with `domain.salt` and `chainUid` (`checkPayment`, CLI-SGN-08), self-call check by allowlist, `TradeOrder`/`DexOrder`/cancel typed data, refuse an unlisted `dex`, no EOA approve, wrap by signature (CLI-SGN-05, CLI-SGN-33…36); KATs with relayed calldata (`dex_order_kat.json`). Open: the app bundle rebuild and the reference ERP's `lib/eip712.py` (bamboo-dms item below).
+- [ ] bamboo-dms (other repo, P5 follow-up; before the P5 node reaches a chain Odoo uses): jobs carry `struct` and the v3 `metatx`/salted digests (`lib/eip712.py` on `metatransfer_kat.json` / `metatx_kat.json`); `metatx_v1_kat.json` moved to `legacy/p5/`, `hedera_kat.json` is v3, the KATs gained `calldata`; the DEX book rows carry `sell_token`, trades list their makers, a failed trade is `{taker: {row, fill}, makers}`, DEX cancels and invalidations come as relay jobs (`mtxCancelOrder`, `mtxInvalidateNonces`, `mtxCancelOrders`), the events are `LegSettled`, `MatchFailed` (`out_of_gas` when empty), `OrderCancelled`, `NoncesInvalidated`; `dex_markets` lose `fee_on`/`fee_recipient`; a consumed `already_invalidated` is success; the mesh vectors are regenerated; deploy JSON keys (`demo_token`, `demo_token_2`; v1 keys gone); the portal's clientkeys bundle is rebuilt.
 
 **Non-EVM families (NM-*)**
 - [ ] **NM-APT** Aptos: `MetaCall`/`MetaTransfer` (BCS), public `scaas::metacall::verify`, `mtx_` entries incl. key and
@@ -143,7 +138,7 @@ chainId 9000 → **7622**; `PqzToken` implements `IERC20MetaTx` (PQZ rev 1.4 R28
       lock per `(from, pay_ref)` (R8-9), DEX needs relayer binding (R8-10); §7.2 `associateUnderlying()` superseded
       (R6-8, TW2 R144); §7.5 add lane-horizon client obligation (RS7-11, RS11-24, RS12-24) + Aptos multisig-wrap risk;
       §1.2/§1.3 immutability now true by ruling; admin-exception list; outbox rules into integration.md.
-- [x] **NODE-IDX-06** rules in the docs (`node/indexer-feeds.md`, `integration.md`); the code is stream MT-8 (node) and the
+- [x] **NODE-IDX-06** rules in the docs (`node/indexer-feeds.md`, `integration.md`); the code is stream MT-8 (node, open after P5) and the
       client refund check.
 - [x] Cross-spec nits, closed by the reorg and the meta-tx fold (checked 2026-10-08): Soroban has no open form
       (`networks/README.md`, [NET-SOR-10]); PAY-FIX6 = the 1271 cap [CTR-DEX-08]; PAY-FIX7 = fee round-up [CTR-DEX-11];
diff --git a/docs/architecture.md b/docs/architecture.md
index 14f0dd5..174f74e 100644
--- a/docs/architecture.md
+++ b/docs/architecture.md
@@ -97,8 +97,7 @@ forced transfer against a recorded order. Among them:
   disables a flag that was not locked, renounces; [CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)), and the role
   holders of those flags, such as the `rateAdmin` (step-capped, timelocked rate changes) and the `guardian` (only
   `disableWrap`) ([CTR-TOK-10](contracts/token-wrappers.md#CTR-TOK-10));
-- the `SCaaSDexV1` `admin` (as built `setMarket` with a market fee of at most 1 %, bounded by each order's signed
-  `maxFeePpm`; specified: four powers — listing, the split of each order's signed fee between relayer and treasury,
+- the `SCaaSDex` `admin` (four powers — listing, the split of each order's signed fee between relayer and treasury,
   exchange targets, listed-only mode — never the amount, [CTR-DEX-03](contracts/dex.md#CTR-DEX-03));
 - the admin `mint` of the standalone non-EVM tokens on Soroban, TON and CosmWasm (a supply power, not a balance power);
 - the TON DEX admin `WithdrawFees` (fees only; bounced payouts are claimed by their owners, [NET-TON-03](networks/ton.md#NET-TON-03));
@@ -220,8 +219,8 @@ uses Zether; hiding the relationship itself is out of scope by design ("not a mi
 
 When every leg is on chain, use one-transaction settlement. When a leg is off chain, anchor the on-chain leg **after**
 the off-chain leg is irrevocable, or give the saga a funded on-chain compensation path. Atomic settlement is BUILT for
-payments (the `pay` op), the DEX (`SCaaSDexV1.settle`, legacy `MetaTxDex`; specified: `SCaaSDex.mtxSettle`, one
-taker against several makers, each leg verified by its sell token) and mandates (`MandateWallet.payUnderMandate`,
+payments (a `MetaTransfer` with `entryRef`), the DEX (`SCaaSDex.mtxSettle`, one taker against several makers, each leg
+verified by its sell token) and mandates (`MandateWallet.payUnderMandate`,
 named `mtxPayUnderMandate`); generic saga orchestration is a client concern.
 
 **Anchoring as proof of action.** For automated agents and workflows the anchor gives a tamper-evident proof that a
@@ -236,8 +235,8 @@ agent signs, a relayer pays gas); Zether keeps commercial amounts confidential w
 
 | Component | Path | Role | Status |
 |---|---|---|---|
-| EVM contracts | `smartcontracts/evm/` (Foundry; `src/{common,metatx,factory,dex,wallet,account,registry,zether,hedera,chains}`) | Target: the token tree `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → kinds `NORMAL`, `WRAPPED`, `NORMAL_ZETHER`, `WRAPPED_ZETHER` ([CTR-TOK-21](contracts/token-wrappers.md#CTR-TOK-21)); the libraries `TradeLib`, `AdminLib`, `WrappedLib`, `ZetherLib`, `HederaLib`, with pay inline behind the `PAYABLE` flag in `MetaTokenBase` (no `PayLib`; [CTR-TOK-24](contracts/token-wrappers.md#CTR-TOK-24)); `OpenFactory` for tokens and DEX clones ([CTR-TOK-25](contracts/token-wrappers.md#CTR-TOK-25)); `SCaaSDex`; `MandateWallet`; `SmartKeyAccount`; `UniversalAccountRegistry`; the Zether verifiers (bn254, BLS12-381), `ZetherDisclosure`, `ZetherStatements`. Build profiles `private7622` (the private chain 7622), `zether`, `gnosis`, `celo` | BUILT (P1a–P1e): `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase`, kind `NORMAL` = `NormalToken`, kind `WRAPPED` = `WrappedToken` (1–8 legs, native-coin leg) + `WrappedLib`, `AdminLib`, `HederaLib`, and `OpenFactory` with `createToken`/`TokenConfig`; still built: the older v1 line (`OpenFactoryV1`) and `ZetherToken`. SPECIFIED: `TradeLib` (P2), the `*_ZETHER` kinds and `ZetherLib` (P3), P4–P5; `PqzToken` |
-| Hedera contracts | the EVM implementations | No separate contracts: the EVM implementations deployed with `IS_HEDERA` (HIP-632 signatures, fail-closed HTS checks; [CTR-TOK-23](contracts/token-wrappers.md#CTR-TOK-23)) | BUILT (P1c–P1d): `IS_HEDERA` is an immutable of every implementation; `HederaLib` (`smartcontracts/evm/src/hedera/`) holds the HIP-632 path, and the HTS association is called from `WrappedLib` init; the Hedera wrapper children are deleted (the v1 `HederaMetaToken` goes with the v1 line) |
+| EVM contracts | `smartcontracts/evm/` (Foundry; `src/{common,metatx,factory,dex,wallet,account,registry,zether,hedera,chains}`) | Target: the token tree `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → kinds `NORMAL`, `WRAPPED`, `NORMAL_ZETHER`, `WRAPPED_ZETHER` ([CTR-TOK-21](contracts/token-wrappers.md#CTR-TOK-21)); the libraries `TradeLib`, `AdminLib`, `WrappedLib`, `ZetherLib`, `HederaLib`, with pay inline behind the `PAYABLE` flag in `MetaTokenBase` (no `PayLib`; [CTR-TOK-24](contracts/token-wrappers.md#CTR-TOK-24)); `OpenFactory` for tokens and DEX clones ([CTR-TOK-25](contracts/token-wrappers.md#CTR-TOK-25)); `SCaaSDex`; `MandateWallet`; `SmartKeyAccount`; `UniversalAccountRegistry`; the Zether verifiers (bn254, BLS12-381), `ZetherDisclosure`, `ZetherStatements`. Build profiles `private7622` (the private chain 7622), `zether`, `gnosis`, `celo` | BUILT (P1a–P1e): `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase`, kind `NORMAL` = `NormalToken`, kind `WRAPPED` = `WrappedToken` (1–8 legs, native-coin leg) + `WrappedLib`, `AdminLib`, `HederaLib`, and `OpenFactory` with `createToken`/`TokenConfig`; `TradeLib` and the `SCaaSDex` clone (P2), the `*_ZETHER` kinds and `ZetherLib` (P3), `MandateWallet` and `SmartKeyAccount` (P4); the v1 line, the old `ZetherToken` and the typed structs in `legacy/` (P3–P5). SPECIFIED: `PqzToken` |
+| Hedera contracts | the EVM implementations | No separate contracts: the EVM implementations deployed with `IS_HEDERA` (HIP-632 signatures, fail-closed HTS checks; [CTR-TOK-23](contracts/token-wrappers.md#CTR-TOK-23)) | BUILT (P1c–P1d): `IS_HEDERA` is an immutable of every implementation; `HederaLib` (`smartcontracts/evm/src/hedera/`) holds the HIP-632 path, and the HTS association is called from `WrappedLib` init; the Hedera wrapper children are deleted (the v1 `HederaMetaToken` is in `legacy/p5/`) |
 | Cosmos contracts | `smartcontracts/cosmos/` (CosmWasm workspace) | `scaas-token` (CW20 + meta-op), `scaas-mandate`, `scaas-dex`, shared `scaas-metaop` | BUILT |
 | Soroban contracts | `smartcontracts/soroban/` | SEP-41 token + `pay`, mandate, DEX; native auth as the meta-tx (Stellar and Pi Network) | BUILT |
 | Move contracts | `smartcontracts/move/{aptos,sui}/` | Package `scaas`: `meta` (per-subject account + lanes), mandate, DEX | BUILT |
@@ -255,10 +254,10 @@ agent signs, a relayer pays gas); Zether keeps commercial amounts confidential w
 </details>
 
 **Target and built.** The contract sections below describe the target that the component docs specify. The built EVM
-code already has the P1 base and the two public kinds (P1a–P1d) and still carries the older lines (the v1 tokens; the old `ZetherToken`
-is in `legacy/p3/`, the typed-struct `SubjectAccount` and `MandateWallet` in `legacy/p4/`); every component doc says what is built in a *Transitional (BUILT)* note naming the
-phase that replaces it: P1 the base, the two public kinds and `createToken` (P1e); P2 `TradeLib` and the DEX clone; P3 the Zether kinds; P4 `MandateWallet` and `SmartKeyAccount` on the
-base (built); P5 node and client support for the new ABI ([contracts/token-wrappers.md](contracts/token-wrappers.md#transitional-built-tokens),
+code has the P1 base, the kinds, the DEX clone, `MandateWallet` and `SmartKeyAccount` on the base (P1–P4), and the node
+and clientkeys on that ABI (P5); the older lines are in `legacy/` (the old `ZetherToken` in `legacy/p3/`, the typed
+structs in `legacy/p4/`, the v1 line in `legacy/p5/`); every component doc says what is built in a *Transitional (BUILT)*
+note naming the phase ([contracts/token-wrappers.md](contracts/token-wrappers.md#transitional-built-tokens),
 [contracts/metatx.md](contracts/metatx.md#transitional-built)). Nothing is deployed, so the target replaces the built
 lines in place; there is no migration between them.
 
@@ -622,7 +621,7 @@ the target; the caption says what is built.
 
 The subject signs on its device, the client's outbox pushes the intent to its own node, and the client books the
 payment only from the finalized feed ([INT-ERP-18](integration.md#INT-ERP-18),
-[NODE-GEN-08](node/README.md#NODE-GEN-08)); built: `mtxPay` on `MetaTokenBase` and the `pay` op of the v1 line.
+[NODE-GEN-08](node/README.md#NODE-GEN-08)); built: the payment `MetaTransfer` and `mtxPay` on `MetaTokenBase` (P1b–P5).
 
 ```mermaid
 sequenceDiagram
@@ -679,8 +678,8 @@ sequenceDiagram
 ### 6.3 DEX order to settlement (target, P2)
 
 Role-free `TradeOrder`s rest in the node's book and settle in one call that pays every party
-([CTR-DEX-15](contracts/dex.md#CTR-DEX-15), [node/dex-venue.md](node/dex-venue.md)); built: DEX-signed orders over
-allowances, `SCaaSDexV1.settle`, `OrderFilled` / `Matched`.
+([CTR-DEX-15](contracts/dex.md#CTR-DEX-15), [node/dex-venue.md](node/dex-venue.md)); built (P2b–P5): `mtxSettle`,
+`LegSettled` / `MatchFailed`.
 
 ```mermaid
 sequenceDiagram
diff --git a/docs/clients/app.md b/docs/clients/app.md
index 85f27df..f44e606 100644
--- a/docs/clients/app.md
+++ b/docs/clients/app.md
@@ -175,7 +175,7 @@ Fake wallets are not duplicated: end-to-end tests inject clientkeys `test/wallet
       "explorer": "https://gnosisscan.io", "native": { "symbol": "xDAI", "decimals": 18 },
       "dev": false, "private": false, "gatewayNode": "main",
       "chainUid": "0x…",                                     // genesis hash = every domain salt (NET-ALL-24)
-      "contracts": { "factoryV1": "0x…", "factoryV2": "0x…", "dex": "0x…",           // dex = SCaaSDexV1
+      "contracts": { "factory": "0x…", "dex": "0x…",               // dex = the venue's SCaaSDex clone
                      "dexes": ["0x…"],                         // the DEX list (NET-ALL-24, SPECIFIED)
                      "smartKeyAccountFactory": "0x…", "uaRegistry": null },
       "tokens": [ { "address": "0x…", "symbol": "EUR-M", "decimals": 6, "label": "Euro meta" } ],  // pinned
@@ -199,9 +199,9 @@ Fake wallets are not duplicated: end-to-end tests inject clientkeys `test/wallet
 
 `key` is the node's `chain_key` (`config.rs:746`); non-EVM curated tokens and assets carry `symbol`/`decimals` the same
 way; a chain without `gatewayNode` has the self-paid path only. `npm run config:from-deployments -- <rpc>` reads
-`smartcontracts/evm/deployments/<chainid>.json` and maps `scaas_dex` → `contracts.dex`, `factory` →
-`contracts.factoryV1`, `token_factory` (was `factory_v2`) → `contracts.factoryV2`, `smart_key_account_factory` (P4; was `subject_account_factory`) → `contracts.smartKeyAccountFactory`;
-the deployment's `dex` key is `MetaTxDex`, a different contract, and is not mapped; other families are written by hand.
+`smartcontracts/evm/deployments/<chainid>.json` and maps `token_factory` → `contracts.factory`, `smart_key_account_factory`
+→ `contracts.smartKeyAccountFactory`; a DEX is a `createDex` clone named by the operator (the v1 keys `factory`, `dex`,
+`scaas_dex` are gone, P5); other families are written by hand.
 Target (SPECIFIED): the deployment file also carries `chain_uid` and the DEX list ([NET-EVM-05](../networks/evm.md#NET-EVM-05)),
 mapped to `chainUid` and `contracts.dexes` (with `contracts.dex` = the venue's DEX, which must be on the list); the
 validator refuses an EVM or Hedera chain without `chainUid`, and at start the app compares it with the RPC's block-0
@@ -268,7 +268,7 @@ the terms. Every adapter receives transports wired to the guarded `fetch` ([CLI-
 
 | Family | Encoders (clientkeys `fam/`) | Subject signs | Gateway | Self-paid | Reads | Events / status |
 |---|---|---|---|---|---|---|
-| **EVM** | `evm.js` + DEX `Order`/`CancelOrder`/`InvalidateNonces`, v2 calldata, `payLane`; v3 `UAMetaTransaction`/`UAMetaTransfer`; KAT `metatx_kat` (v3), `metatx_v1_kat` (built v1, until P5), `metatransfer_kat`, `dex_kat`, `vectors/ua/*` | EIP-712 (`eip712Domain()` checked); EOA, ERC-1271 SmartKeyAccount, or `UAKey.signUA("metatx", digest)` for a UA | `/v1/metatx`; `/v1/ua-metatx` | `executeMetaTransaction` / named `mtx*` / `ua*`; the direct function when signer = submitter | `balanceOf`, `balanceOfUA`, `mtxNonce` (v1 line: `metaNonce`), `uaNonce`, `payLane`, `versionOf` | `eth_getLogs` (bounded) |
+| **EVM** | `evm.js` + `TradeOrder`/`DexOrder`/`CancelOrder`/`InvalidateNonces`, `MetaTransfer`, `payLane`; v3 `UAMetaTransaction`/`UAMetaTransfer`; KAT `metatx_kat`, `metatransfer_kat`, `trade_kat`, `dex_order_kat`, `vectors/ua/*` | EIP-712 (`eip712Domain()` checked); EOA, ERC-1271 SmartKeyAccount, or `UAKey.signUA("metatx", digest)` for a UA | `/v1/metatx`; `/v1/ua-metatx` | `mtxExecute` / `mtxExecuteTransfer` / named `mtx*` / `ua*`; the direct function when signer = submitter | `balanceOf`, `balanceOfUA`, `mtxNonce`, `uaNonce`, `payLane`, `versionOf` | `eth_getLogs` (bounded) |
 | **Hedera** | EVM + `hedera_kat` | ECDSA alias via extension; ED25519 `0.0.N` raw over the digest via seed (`hedera_ed25519`) | `/v1/metatx` (64-byte signatures allowed) | as EVM via the relay | as EVM; mirror for `0.0.N` ⇄ address, associations, HTS info | relay logs; mirror tx |
 | **Cosmos** | `fam/cosmos.js` | ADR-036 via Keplr/Leap or seed `m/44'/118'/0'/0/i` | `/v1/ops` | `MsgExecuteContract{Relay}` signed + broadcast by the user | CW20 `Balance`, `Nonce{owner, lane}` | tx search; `getTx` |
 | **Soroban** | `fam/soroban.js` | Freighter `signAuthEntry`, or seed `m/44'/148'/i'` (Pi coin 314159): sha256 of the auth preimage (`G…`) / `Ed25519{key_id, sig}` (`C…`) | `/v1/ops` | user = transaction source: simulate, attach auth, sign the envelope hash (only via `buildSelfPaid`) | SEP-41 `balance`; random nonce | `getEvents`, `getTransaction` |
@@ -410,7 +410,7 @@ the non-EVM families: `/v1/ops`, Hedera on `/v1/metatx`). Why: with gateway subm
 family. Cost: until those routes exist, Hedera and non-EVM are self-paid only.
 
 <a id="intent-status"></a><a id="CLI-APP-08"></a>**CLI-APP-08** — **Intent status is chain truth.** A `202` means "accepted by
-relayer". *Done* = the nonce is consumed (`mtxNonce` (v1 line: `metaNonce`) / `uaNonce` / the family lane read), plus `PaymentSettled` /
+relayer". *Done* = the nonce is consumed (`mtxNonce` / `uaNonce` / the family lane read), plus `PaymentSettled` /
 `MetaTransactionExecuted` / `UAMetaTransactionExecuted` when present. *Expired* = `validUntil` passed with the nonce
 unconsumed. `GET /v1/intents/{id}` is used when the node returns an id. Why: the node is trusted for liveness, not truth.
 Cost: one read per poll.
@@ -750,7 +750,7 @@ Unit (Vitest / `node --test`, no network):
 
 | Area | Vectors / method |
 |---|---|
-| EVM encoders | `metatx_kat` (v3), `metatx_v1_kat` (built v1, until P5), `metatransfer_kat`, `dex_kat`, `hedera_kat`, `wrap_rate_vectors`, `smart_key_account_create2`, `smart_key_account_kat`, `mandate_pay_kat`, `mandate_revoke_kat`, `webauthn_soft` |
+| EVM encoders | `metatx_kat`, `metatransfer_kat`, `trade_kat`, `dex_order_kat` (relayed calldata too), `hedera_kat`, `wrap_rate_vectors`, `smart_key_account_create2`, `smart_key_account_kat`, `mandate_pay_kat`, `mandate_revoke_kat`, `webauthn_soft` |
 | Non-EVM encoders (clientkeys) | `mesh-envelope-v1.2.json` cross-language payloads, `ton-vectors.json`, `fam_*.json` per family, `sui_vectors.json`, the seed-signed vectors, `solana_derivation.json` |
 | UA (clientkeys) | `smartcontracts/vectors/ua/*`: ids, keyHash, `ua_msg`, PoP, `UAMetaTransaction` digests; `deriveUAKey` paths under `m/7622'` |
 | Backup / vault | `backup_policy.json` plus the de-duplication and `msig` rows; `vault_v2_fixture.json` |
diff --git a/docs/clients/signers-clientkeys.md b/docs/clients/signers-clientkeys.md
index 254c3c2..8c5ad77 100644
--- a/docs/clients/signers-clientkeys.md
+++ b/docs/clients/signers-clientkeys.md
@@ -189,7 +189,7 @@ is signed only after a form showing the account, the selector and value 0. BUILT
 (with its `decimals` and `symbol`) from the signer's own chain profile (an app/extension build-time or user-pinned
 registry), never from the server response, and refuses `verifyingContract ≠ expectedToken`. A portal page served by the
 same server that serves the typed data cannot be defended this way (it ships the signer code); that case is out of scope.
-Test: server data with a different token but the expected symbol ⇒ refused.
+Test: server data with a different token but the expected symbol ⇒ refused. BUILT in clientkeys (P5, `expectedToken`).
 
 <a id="CLI-SGN-27"></a>**CLI-SGN-27** — **Check, then sign exactly what was checked.** `fam.checkTerms(start, shown)`
 rebuilds the payload with `fam/<family>.js` and returns a frozen `checked` object `{ payload, walletInput, signingBytes
@@ -215,18 +215,18 @@ from a malicious issuer; in the app, `shown` is the user's own input. Why: it cl
 ### 5.1 Meta-transaction calls and trade orders
 
 <a id="CLI-SGN-33"></a>**CLI-SGN-33** — **Every SCaaS EIP-712 domain is built with `salt = chain_uid` from the
-signer's own chain profile, and a different salt is refused.** Status: **SPECIFIED**. The app, the portal signer and
+signer's own chain profile, and a different salt is refused.** Status: clientkeys **BUILT** (P5), the app **SPECIFIED**. The app, the portal signer and
 clientkeys fill `domain.salt` with the chain profile's `chain_uid` ([NET-ALL-24](../networks/README.md#NET-ALL-24)),
 which works offline, or from the contract's `eip712Domain()` read once and cached; clientkeys refuses typed data whose
 `salt` differs from its pinned profile, or a domain without one for a SCaaS contract. This covers tokens (transfers,
 payments, self-calls, trade orders), mandate wallets, subject accounts, the DEX and the registry. What protects the
 user is the contract — a contract on another chain computes its digest with that chain's `chain_uid`, so the signature
 fails there whichever wallet made it; the client check catches a wrong profile or a hostile server before the user is
-asked. Transitional (BUILT): clientkeys builds and checks `salt` for the Universal Account (PoP flow,
-[integration.md](../integration.md)) and, since P4, the `SmartKeyAccount` owner call; the v1 token checks stay unsalted (P5).
+asked. Built (P5): clientkeys builds and checks `salt` for the Universal Account (PoP flow,
+[integration.md](../integration.md)), the owner call, payments, self-calls and trade orders; no unsalted check is left.
 
 <a id="CLI-SGN-34"></a>**CLI-SGN-34** — **A meta-transaction's `data` is decoded and shown before the user signs;
-a selector outside the token's allowlist is refused.** Status: **SPECIFIED**. clientkeys and the app encode
+a selector outside the token's allowlist is refused.** Status: clientkeys `checkCall` **BUILT** (P5, the allowlist pinned by the caller). clientkeys and the app encode
 `mtxExecute` calldata themselves, and before any signature decode `data` against the implementation's published
 allowlist (`mtxSelectors()`, pinned per implementation version in the chain profile, cross-checked with the chain):
 the selector's function name and every argument in human terms (amounts with the token's decimals, recipients,
@@ -240,7 +240,7 @@ with no override. The same applies to `MandateWallet`, `SmartKeyAccount` and any
 the meta-transaction) and an order lane (`batch` of a trade order) are labelled differently wherever both appear.
 
 <a id="CLI-SGN-35"></a>**CLI-SGN-35** — **A trade order names a DEX on the chain profile's list, or the client refuses
-to build and sign it.** Status: **SPECIFIED**. Before signing a `TradeOrder` (in the app, clientkeys or a portal)
+to build and sign it.** Status: clientkeys `checkTradeOrder` **BUILT** (P5). Before signing a `TradeOrder` (in the app, clientkeys or a portal)
 the review shows `dex`, `relayer`, `destination`, the price limit both ways, the signed `fee` rate and the effective
 minimum fill per settlement (`max(minFill, ceil(amount / 2))`; a `minFill` below half is shown as half; `minFill =
 amount` as fill-or-kill). By default the client **refuses** to build or sign when `dex` is not on its pinned chain
@@ -254,7 +254,7 @@ the signer is the last place a phishing `dex` can be stopped. Cost: a new DEX ne
 trade on it.
 
 <a id="CLI-SGN-36"></a>**CLI-SGN-36** — **A client never asks an EOA to approve a SCaaS token; wrapping a SCaaS
-underlying is signed, not approved.** Status: **SPECIFIED**. On a SCaaS token only a contract may call `approve`
+underlying is signed, not approved.** Status: **BUILT** in clientkeys (P5: no approve builder; `checkTradeOrder` with `wrappers`). On a SCaaS token only a contract may call `approve`
 ([CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)), and `approve` is on no token allowlist, so no client offers
 an approve screen, typed data or permit for one. A wrap whose underlying is a SCaaS token is a `TradeOrder` signed in
 the **underlying's** domain with `dex` = `receiveToken` = the wrapper, `receiveAmount` = the minimum to mint,
@@ -703,7 +703,7 @@ Built entry points (BUILT; load only what the chosen signer needs):
 
 | Entry | Exports (main) | Use |
 |---|---|---|
-| `passkey-signer.js` | `passkeySupported`, `creationOptions` (PRF on), `requestOptions`, `publicKeyFromSpki`, `derToRS`, `encodeAssertion`, `hashTypedData`, `passkeySubjectKey`, `accountSignature`, `merkleBatch`, `checkOwnerCall`, `checkPayment` | create a passkey, sign `challenge = digest`, encode for `SmartKeyAccount.isValidSignature` |
+| `passkey-signer.js` | `passkeySupported`, `creationOptions` (PRF on), `requestOptions`, `publicKeyFromSpki`, `derToRS`, `encodeAssertion`, `hashTypedData`, `passkeySubjectKey`, `accountSignature`, `merkleBatch`, `checkOwnerCall`, `checkPayment`, `checkCall`, `checkTradeOrder`, `metaTransferTypedData`, `tradeOrderTypedData`, `orderCancelTypedData` (both bundles) | create a passkey, sign `challenge = digest`, encode for `SmartKeyAccount.isValidSignature` |
 | `seed-signer.js` | `normalizeMnemonic`, `wordsToEntropy`, `seedFromEntropy`, `deriveKey`, `signDigest`, `NETWORKS`, `createVault`, `openVault`, `enablePrf`, `rewrapPin`, `SeedBackup`, `wipe` | 24-word vault: generate, back up (3-word challenge), unlock by PRF or PIN, derive per family, sign digests |
 | `zether-keys.js` (`zether.js`) | `deriveConfKey`, `confPublic` (returns the tagged UA once Universal Accounts land), `zetherPop` (signs the new PoP; `popMessage` removed), `sealConfKey`/`openConfKey`, `checkBalance`, cache helpers, `readBalance` | confidential keys and balance cache; proofs via the prover WASM `zetherCall(cmd, json)` (`keygen`, `encrypt`, `decrypt`, `decryptPending`, `checkBalance`, `proveTransfer`, `proveBurn`, `verifyTransfer`, `verifyBurn`, `pop`, `fundCalldata`, `envelope`) |
 
diff --git a/docs/contracts/dex.md b/docs/contracts/dex.md
index 48072d8..84212e7 100644
--- a/docs/contracts/dex.md
+++ b/docs/contracts/dex.md
@@ -5,9 +5,8 @@ and whose settlement contract settles signed orders on chain. Users never pay ga
 messages that a relayer submits, and a SCaaS token needs **no allowance** to trade — its order is verified by the token
 itself, which moves funds only into the DEX the signer named. Status: the target of this file (token-verified
 `TradeOrder`s, `SCaaSDex.mtxSettle`, outside-token legs, one signed fee rate, the exchange path against AMMs
-`mtxExchange`, the `DexPuller`) **SPECIFIED**, **BUILT** (`SCaaSDex`, P2b-1, P2b-2, P2c);
-`SCaaSDexV1` (DEX-signed orders over allowances, the node's DEX until P5) and the legacy `MetaTxDex` are **BUILT**
-([Transitional](#transitional-built)); non-EVM settlement programs **BUILT** with the fixes below **SPECIFIED**.
+`mtxExchange`, the `DexPuller`) **BUILT** (`SCaaSDex`, P2b-1, P2b-2, P2c; the node's venue on it, P5); `SCaaSDexV1` and
+`MetaTxDex` are in `legacy/p5/` ([Transitional](#transitional-built)); non-EVM settlement programs **BUILT** with the fixes below **SPECIFIED**.
 
 **Contents**
 
@@ -419,7 +418,7 @@ does, [CTR-ACC-05](accounts.md#CTR-ACC-05)), else 50 k; at most 32 bytes of retu
 requires `gasleft() ≥ cap · 64/63 + margin`, otherwise the whole transaction reverts (EIP-150: a relayer must not
 starve the call to turn a valid signature into an invalid one). `mtxCancelOrders` needs no `try`: a capped check
 only returns `false` ⇒ the item is skipped. The node does not restore an ERC-1271 order whose settlement failed out of
-gas. Why: the built contract calls `SignatureChecker` without a cap (`SCaaSDexV1.sol:383-384`), so a contract maker
+gas. Why: the v1 DEX called `SignatureChecker` without a cap (`SCaaSDexV1.sol:383-384`, `legacy/p5/`), so a contract maker
 that answers correctly under `eth_call` but burns gas or returns huge returndata in the real block breaks a whole
 `settle` batch (the remaining 1/64 gas is not enough for the next pairs) and **every** `cancel` batch. SCaaS legs get
 the same cap inside their token. Status **BUILT** (P2b-2).
@@ -502,54 +501,20 @@ intake fails alone (`MatchFailed`). The node side (home-bound orders only, the f
 
 <a id="legacy-metatxdex"></a><a id="relayer-fee-rounding"></a>
 
-`SCaaSDexV1` (`src/dex/SCaaSDexV1.sol`, the DEX built before P2b, renamed; the new `SCaaSDex` is a different contract) is still deployed by the script for the node (`dex.rs`, `dex_kat.json`, e2e key `scaas_dex`) until P5, then moves to `legacy/` (owner: backup, not delete). The rest of this section is `SCaaSDexV1`; the rebuild replaces it (a new deployment; users re-sign their resting orders):
-
-- **Orders.** `SCaaSDexV1` signs orders on the DEX, `name = "SCaaS Dex"`, `version = "1"`, `chainId`, `verifyingContract = DEX`, no salt: `Order(address
-  maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,uint256 nonce,uint256 expiry,uint32 maxFeePpm,uint8 flags,address
-  relayer,uint8 feeMode,uint256 fee,address feeToken,address feeRecipient)` — `maker` the signer, `taker` 0 = anyone or only this counterparty (RFQ), `nonce` unique
-  per maker (clients use `unix_ms·2^20 + random20`), valid while `nonce >= minNonce[maker]`, `maxFeePpm` the highest market fee accepted in any role, flags bit0
-  `FOK`, bit1 `IOC`.
-- **`settle(Match[]) returns (bool[])`**, `Match = {ref, maker, makerSig, taker, takerSig, makerFill, takerFill}` (`makerFill` of `maker.sellToken`, `takerFill` of
-  `taker.sellToken`), one pair per `try this.settleOne(m, msg.sender)` — atomic per pair, a failing pair emits `MatchFailed`, none ⇒ `NothingSettled`; the real
-  relayer is passed in because inside the self-call `msg.sender == DEX`. Checks before any transfer: flags valid, `block.timestamp <= expiry`, nonce, relayer,
-  `taker` ∈ {0, counterparty}, signature; `M.sellToken == T.buyToken`, `M.buyToken == T.sellToken`, `sellToken != buyToken`, `M.maker != T.maker`, market listed;
-  `makerFill > 0`, `takerFill > 0`, `filled[h] + fill <= sellAmount`, FOK ⇒ `filled[h] == 0 && fill == sellAmount`; price `takerFill · M.sellAmount >= makerFill ·
-  M.buyAmount` and `makerFill · T.sellAmount >= takerFill · T.buyAmount`; `feeOn ⇒ makerPpm <= M.maxFeePpm && takerPpm <= T.maxFeePpm`. Then direct
-  `transferFrom(payer → payee)`: M → T `makerFill − takerDexFee`, T → M `takerFill − makerDexFee`, `takerDexFee = makerFill · takerPpm / 1e6` and `makerDexFee =
-  takerFill · makerPpm / 1e6` to the market fee recipient, each order's relayer fee on top; events `emit OrderFilled(ref, hash, owner, Fill)` per side and `emit
-  Matched(ref, makerHash, takerHash)`. The book fills at the maker's price, `takerFill = ceil(makerFill · M.buy / M.sell)`. IOC remainders are closed after the loop
-  (`filled = sellAmount`).
-- **Fees.** `setMarket(base, quote, listed, feeOn, makerPpm, takerPpm, feeRecipient)`, cap `FeePolicy.MAX_FEE_PPM`, `feeRecipient ∉ {0, DEX}`; the market fee per
-  fill rounds down, `fill * ppm / PPM` (`SCaaSDexV1.sol:216-217`; with `ppm > 0` the fix is `Math.mulDiv(fill, ppm, PPM, Math.Rounding.Ceil)`, `ppm ≤ MAX_FEE_PPM` ⇒
-  `fee ≤ fill` and `fee · PPM ≥ fill · ppm`, tested with `ppm = 3_000` and `feeOn = false`; the floor test `test_feeOnSplitsReceivedAmountsWithoutDust`,
-  `SCaaSDexV1.t.sol:439-454`, changes to round up). The relayer fee uses `FeeMode`: `PERCENT` in `sellToken` (`feeToken ∈ {0, sellToken}`,
-  `FeePolicy.compute(PERCENT, fill, fee)`), `FIXED` pro-rata `fee · fill / sellAmount` rounded down (paid in `sellToken` it needs `fee <= 1 % · sellAmount`,
-  `FeePolicy.compute(FIXED, sellAmount, fee)`); recipient `feeRecipient` or the sender; `feeRecipient = DEX` reverts `FeeWouldStick`. Invariants: `filled[h] <=
-  sellAmount`; `received + fee == fill` per leg.
-- **Allowance.** The DEX is the only spender; users approve it gaslessly with the token's meta-tx op `approve(address spender,uint256)`, `data = approve(address
-  spender,uint256 amount)` (68 bytes; `m.value == 0`, `m.to == spender`, spender a contract; executed as `_approve(from, spender, amount)`), on a random lane
-  (`keccak("scaas.dex.approve" ‖ rand)`), relayer fee forced to 0 (`test_approveOpRelayerFeeIsCappedToZero`). Intake read `checkOrder(Order o, bytes sig) view
-  returns (bytes32 hash, uint8 status, uint256 remaining, uint256 fundable, uint256 feeFundable)`, `fundable = min(balanceOf, allowance(DEX))`, `status` ∈ `OK,
-  BAD_FLAGS, EXPIRED, NONCE_INVALID, BAD_SIG, CLOSED, NOT_LISTED, BAD_FEE` (`SCaaSDexV1.sol:93-100`); the node compares `maxFeePpm` with the market fee (`dex.rs:565,
-  616-624`).
-- **Cancel.** `cancel(CancelReq[])` — `cancel(CancelReq[] reqs)`, `CancelReq = {Order order; bytes sig}`: a `CancelOrder(hash(o))` signature sets `filled[h] =
-  o.sellAmount`; `invalidateNonces(maker, newMin, sig)` (signed as `invalidateNonces(maker, minNonce, sig)`) with `minNonce <= 2^128 − 1` (`type(uint128).max`,
-  `SCaaSDexV1.sol:89`). The 1271 branch has no cap (`MetaToken.sol:141-143` caps the token side only).
-- **Legacy `MetaTxDex`** (no gateway route, `ReentrancyGuardTransient`, no owner or sweep): two `MetaTransaction` legs with `data = trade(counterToken,
-  minCounterValue, counterparty)`, `to = relayer = MetaTxDex`, `MODE_RESTRICT_RELAYER`, so the token executes a leg only when `relayer == to == msg.sender`.
-  `settle(Leg a, Leg b)`, `Leg = {IERC20MetaTx token; MetaTransaction m; bytes sig}`: `a.token != b.token`, `a.m.from != b.m.from`, `termsA.counterToken == b.token`,
-  `b.m.value >= termsA.minCounterValue` (and symmetrically); a leg with `feeMode != NONE` needs `feeRecipient != 0` and `!= this` (else the default `feeRecipient =
-  msg.sender` would strand it); `executeMetaTransaction` on both tokens, the measured delta must equal `m.value`; it pays `a.m.value` to `b.m.from` and `b.m.value`
-  to `a.m.from` with `SafeERC20.safeTransfer` and `emit TradeSettled(a.m.from, b.m.from, a.token, b.token, a.m.value, b.m.value)`. Fill-or-kill; the surplus
-  `b.m.value > minCounterValue` belongs to the seller of leg A.
-
-`MetaTxDex` stays (built and deployed) until its planned removal (P5, to `legacy/`). The rebuild (`SCaaSDex`, P2b-1, P2b-2, P2c) drops its trade and approve ops, renames `settle`/`cancel`/`invalidateNonces` to `mtxSettle`/`mtxCancelOrders`/`mtxInvalidateNonces`, keeps the DEX-domain `Order` only as `DexOrder`, allowances only to the `DexPuller`, the relayer fee only as its share of the signed DEX fee, and adds the exchange path ([CTR-DEX-20](#CTR-DEX-20)…[-23](#CTR-DEX-23)).
+`SCaaSDexV1` (DEX-signed `Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,uint256 nonce,uint256 expiry,uint32 maxFeePpm,uint8 flags,address relayer,uint8 feeMode,uint256 fee,address feeToken,address feeRecipient)` over allowances to the DEX, `settle(Match[])` pair by pair, a market fee per side
+rounded down plus a separate relayer fee in `feeToken`, `checkOrder`, `cancel`, `invalidateNonces`, an uncapped ERC-1271
+check) and the legacy `MetaTxDex` (two `MetaTransaction` legs with the token's `trade` op; the 68-byte `approve` op) left the build in P5 with the
+v1 token line (`smartcontracts/evm/legacy/p5/`, with their tests and the vector `dex_kat.json`; owner: backup, not
+delete); the node's venue moved to `SCaaSDex` in the same release. The rebuild (`SCaaSDex`, P2b-1, P2b-2, P2c) dropped
+the trade and approve ops, renamed `settle`/`cancel`/`invalidateNonces` to `mtxSettle`/`mtxCancelOrders`/`mtxInvalidateNonces`,
+keeps the DEX-domain `Order` only as `DexOrder`, allowances only to the `DexPuller`, the relayer fee only as its share
+of the signed DEX fee, and adds the exchange path ([CTR-DEX-20](#CTR-DEX-20)…[-23](#CTR-DEX-23)).
 
 ## 14. Conformance
 
 | Layer | Tests |
 |---|---|
-| forge | Path A and Path B, one taker × many makers; `mtxTrade` on a closed, cancelled or IOC-pulled order and with `sellFill = 0` reverts; Path B `sellFill ≠ amount` reverts; `dex` = EOA refused; caller ≠ `dex` refused; every `mtxTrade` error; effective minimum fill for taker and makers incl. the remainder close and `minFill > amount`; FOK via `minFill = amount`; taker fee charged once on the aggregate; split rounding; conservation (unit + invariant: the DEX holds 0 after every handler sequence; for the new DEX the unit tests are built in `test/v2/Dex.t.sol` (P2b-1: settle with two makers, maker rounding, aggregate fee, Path B fee, signed `minFill` and refund, Path A figures seen by the token, isolated failure, arrangement checks, `createDex` and the DEX catalogue, registry, fee split, salted domain) and `test/v2/DexOutside.t.sol` (P2b-2: outside legs through the puller, `DexOrder` digest, `ESCROW` refused, DEX cancels, the ERC-1271 cap by codehash, hostile 1271 signers in settle and cancel batches, the bounded `MatchFailed` reason, a starved check reverting the call, fee-on-transfer, rebasing and no-return tokens) and `test/v2/DexExchange.t.sol` (P2c: routes through mock routers, v2-style pairs and executors, cycles, Path B and outside legs, surplus and remainder, leftovers, `InsufficientOutput`, the interaction blocklist, `LISTED_POOLS` × `setListedOnly`, hostile targets and executors, allowances reset, a fee-on-transfer sell token; the Uniswap fork test is open), and the invariant suite is open); `DexOrder` legs incl. a fallback-only "token" classified outside and `ESCROW` refused; cancel per token and per DEX (signature, replay, lane cap); ERC-1271 maker under the 400 k cap; a 1271 maker that burns gas or returns a returndata bomb inside a multi-settlement call (the others still settle) and inside a cancel batch; replay of an order on another token, another DEX or another chain fails; salted-domain KATs for `TradeOrder`, `CancelOrder`, `InvalidateNonces` → `test/vectors/trade_kat.json` (built, P2a); `DexOrder` → `test/vectors/dex_kat.json`, which stays the `SCaaSDexV1` `Order` vector the node reads (controller ruling, pending the owner); the fee round-up cases above; exchange path: an interaction calling `mtxTrade` of a resting order, targeting the DEX or the puller, or `transferFrom(victim, …)` (all refused or failing); surplus split over several legs receiving one token, remainder to the last; a sold-only or intermediate leftover reverts; `InsufficientOutput`; a profitable cycle X→X; multi-hop through mock Uniswap v2/v3 and a fork test with real Uniswap bytecode on anvil; `LISTED_POOLS` × `setListedOnly` on both entry points; an executor returning less (revert) or more (distributed), re-entering, calling `mtxTrade` or the puller; `receiveToken == this` on the token; a Path B leg; an outside leg through the puller in `mtxSettle` and `mtxExchange`; a reverting and a gas-burning target; invariant: between calls the DEX holds 0 of every token and residual allowances move nothing |
+| forge | Path A and Path B, one taker × many makers; `mtxTrade` on a closed, cancelled or IOC-pulled order and with `sellFill = 0` reverts; Path B `sellFill ≠ amount` reverts; `dex` = EOA refused; caller ≠ `dex` refused; every `mtxTrade` error; effective minimum fill for taker and makers incl. the remainder close and `minFill > amount`; FOK via `minFill = amount`; taker fee charged once on the aggregate; split rounding; conservation (unit + invariant: the DEX holds 0 after every handler sequence; for the new DEX the unit tests are built in `test/v2/Dex.t.sol` (P2b-1: settle with two makers, maker rounding, aggregate fee, Path B fee, signed `minFill` and refund, Path A figures seen by the token, isolated failure, arrangement checks, `createDex` and the DEX catalogue, registry, fee split, salted domain) and `test/v2/DexOutside.t.sol` (P2b-2: outside legs through the puller, `DexOrder` digest, `ESCROW` refused, DEX cancels, the ERC-1271 cap by codehash, hostile 1271 signers in settle and cancel batches, the bounded `MatchFailed` reason, a starved check reverting the call, fee-on-transfer, rebasing and no-return tokens) and `test/v2/DexExchange.t.sol` (P2c: routes through mock routers, v2-style pairs and executors, cycles, Path B and outside legs, surplus and remainder, leftovers, `InsufficientOutput`, the interaction blocklist, `LISTED_POOLS` × `setListedOnly`, hostile targets and executors, allowances reset, a fee-on-transfer sell token; the Uniswap fork test is open), and the invariant suite is open); `DexOrder` legs incl. a fallback-only "token" classified outside and `ESCROW` refused; cancel per token and per DEX (signature, replay, lane cap); ERC-1271 maker under the 400 k cap; a 1271 maker that burns gas or returns a returndata bomb inside a multi-settlement call (the others still settle) and inside a cancel batch; replay of an order on another token, another DEX or another chain fails; salted-domain KATs for `TradeOrder`, `CancelOrder`, `InvalidateNonces` → `test/vectors/trade_kat.json` (built, P2a); `DexOrder`, the DEX cancels and the `mtxSettle` calldata → `test/vectors/dex_order_kat.json` (built, P5; read by the node and clientkeys); the fee round-up cases above; exchange path: an interaction calling `mtxTrade` of a resting order, targeting the DEX or the puller, or `transferFrom(victim, …)` (all refused or failing); surplus split over several legs receiving one token, remainder to the last; a sold-only or intermediate leftover reverts; `InsufficientOutput`; a profitable cycle X→X; multi-hop through mock Uniswap v2/v3 and a fork test with real Uniswap bytecode on anvil; `LISTED_POOLS` × `setListedOnly` on both entry points; an executor returning less (revert) or more (distributed), re-entering, calling `mtxTrade` or the puller; `receiveToken == this` on the token; a Path B leg; an outside leg through the puller in `mtxSettle` and `mtxExchange`; a reverting and a gas-burning target; invariant: between calls the DEX holds 0 of every token and residual allowances move nothing |
 | non-EVM | a third party settling on Cosmos/Soroban/TON fails; `min_nonce` above the cap refused; a dust fill pays fee 1 |
 | e2e (anvil 31950–31959, gateway 18650–18659) | two orders through the gateway → partial match → settle job → balances, no `approve` for SCaaS tokens; cancel ⇒ settle never runs; venue restart ⇒ book intact |
 | managed markets (forge) | one e2e with a regulated equity and an unregulated stablecoin: frozen maker, ineligible taker, ineligible fee recipient, an eligible pair settles |
diff --git a/docs/contracts/metatx.md b/docs/contracts/metatx.md
index 55a1f80..eebc7c9 100644
--- a/docs/contracts/metatx.md
+++ b/docs/contracts/metatx.md
@@ -163,8 +163,7 @@ hashes it itself). Canonical zeroing (`relayer`/`feeRecipient` = 0 when their fl
 
 They are locked by known-answer vectors generated by forge (`vm.writeJson`):
 `smartcontracts/evm/test/vectors/metatx_kat.json` (v3 `MetaTransaction`, `MetaTxBase`) and `metatransfer_kat.json` (`MetaTransfer`);
-`metatx_v1_kat.json` is the built v1 struct (`LegacyMetaTransaction`), read by scaas-node and clientkeys until P5,
-the two v3 vectors written by `TokenKat.t.sol` on a `NormalToken` clone, each with domain (with `salt`), struct, `structHash`, digest and the signature of key `0xA11CE`; the `MandateWallet` and
+the v1 vector `metatx_v1_kat.json` is in `legacy/p5/` (P5), the two v3 vectors written by `TokenKat.t.sol` on a `NormalToken` clone, each with domain (with `salt`), struct, `structHash`, digest and the signature of key `0xA11CE`; the `MandateWallet` and
 `SmartKeyAccount` vectors are `MetaTransaction` vectors in their own domains (`mandate_pay_kat.json`, `mandate_revoke_kat.json`, `smart_key_account_kat.json`, P4). The contract, node and client tests read
 the same files; changing a typehash turns three tests red. Clients decode `MetaTransaction.data` against the
 contract's published allowlist (`mtxSelectors()`) and show the selector and its arguments before asking for a
@@ -888,63 +887,28 @@ Foundry (`forge test`, default profile and `private7622`):
   ERC-1271; EOA `approve` refused.
 - Invariants (`StdInvariant`): `Σ balances == totalSupply`; wrapper solvency; the DEX holds 0 after every handler
   sequence.
-- `MetaTxGas.t.sol` re-measured; `test_metaTxTypehashIsPinned` and `test_metaTransferTypehashIsPinned` pin the two
+- `MetaTxGasV2.t.sol` re-measured; `test_metaTxTypehashIsPinned` and `test_metaTransferTypehashIsPinned` pin the two
   typehashes.
-- KAT: `test/vectors/metatx_kat.json` (v3 `MetaTransaction`, `MetaTxBase`) and `metatransfer_kat.json` (`MetaTransfer`); `metatx_v1_kat.json` = the built v1 struct, read by scaas-node and clientkeys until P5; with the salted
+- KAT: `test/vectors/metatx_kat.json` (v3 `MetaTransaction`, `MetaTxBase`) and `metatransfer_kat.json` (`MetaTransfer`), each with its relayed calldata (P5); with the salted
   domain, plus `mtxpay` vectors and `mtxExecute` calldata vectors for every allowlisted selector
   ([token-wrappers.md](token-wrappers.md#conformance)); `MandateWallet` and `SmartKeyAccount` `MetaTransaction` vectors in
   their domains.
-- Node (`cargo test`): digest == KAT; `data` decode/encode against the allowlist; canonical re-encoding of dynamic
-  selectors; the integration tests (`--ignored`, need `anvil` + `forge`) deploy, sign, submit for real and read the
-  events back.
+- Node (`cargo test`, BUILT P5): digest and calldata == KAT; the allowlist check (`guard.rs`); canonical re-encoding of
+  dynamic selectors not built; the integration tests (`--ignored`, need `anvil` + `forge`) deploy, sign, submit, read back.
 
 ## <a id="transitional-built"></a>16. Transitional (BUILT)
 
 <a id="transitional-built"></a>
 <a id="v1"></a>
 
-The v1 line still runs on the legacy base with a hand-written op dispatch, as Zether did until P3 (each item is removed by the rule
-named in brackets). The v2 tiers run on the new tree (last bullet).
-
-- **Bases** ([CTR-MTX-07](#CTR-MTX-07)). v1: the `ERC20MetaTxV1` mixin + `MetaToken` (kind `META`, tiers 1 and 2 in one
-  implementation; tier 2 reads `IERC20Metadata(underlying).decimals()` at init, mints only through `wrap` and keeps
-  `underlying.balanceOf(this) >= totalSupply`; `unwrap(amount, recipient)`; `initialSupply == 0 && minter == 0` else
-  `WrapperHasNoMint`; errors `NotMinter`, `NotAWrapper`) and `HederaMetaToken`; the Zether kinds are on `MetaTokenBase` (P3; the old `ZetherMetaTx` is in `legacy/p3/`). Invariants as
-  built: `Σ balance == totalSupply`; wrapper `reserve >= totalSupply`, fuzzed as `reserve >= supply`.
-- **Signature checks** ([CTR-MTX-25](#CTR-MTX-25)). Built (P1a): `SigCheck` serves `MetaTxBase` and the built bases
-  `ERC20MetaTxV1`, `ERC20MetaTx` (and the Zether kinds through `MetaTokenBase`, P3), `MandateWallet` and `SmartKeyAccount`
-  (on `MetaTxBase`, P4; the account checks its own keys); `SigLib` is deleted. The v1 `SCaaSDexV1` keeps its own check.
-- **Structs** ([CTR-MTX-15](#CTR-MTX-15), [CTR-MTX-23](#CTR-MTX-23)). v1 (and the pre-P3 Zether line, `legacy/p3/`): one 11-field
-  `MetaTransaction{from, to, value, data, batch, nonce, validUntil, mode, relayer, fee, feeRecipient}` (typehash
-  `MetaTransaction(address from,address to,uint256 value,bytes data,…)`) carries transfers (`data` empty), payments
-  (`data = pay(bytes32)`) and the ops below, named `MetaTxLib.LegacyMetaTransaction` (typehash unchanged, vector
-  `metatx_v1_kat.json`). Before P4, `MandateWallet` and `SmartKeyAccount` verified their own typed structs (`legacy/p4/`).
-- **Domains** ([CTR-MTX-02](#CTR-MTX-02)). v1 `("SCaaS MetaToken", "1", chainId, clone)`; no salt.
-- **Dispatch** ([CTR-MTX-17](#CTR-MTX-17), [CTR-MTX-19](#CTR-MTX-19)). v1 `executeMetaTransaction(m, signature)` runs
-  the legacy steps: relayer, expiry, mode, `m.nonce == metaNonce(from, batch)`, signature, then the fee and `_checkOp`,
-  the fee transfer, `_executeOp`, and the event with the nonce increment. Ops, by `data`:
-
-  | `data` | Length | Check | Effect |
-  |---|---|---|---|
-  | empty | 0 | balance | `transfer(from → to, value)` |
-  | `pay(bytes32 entryRef)` | 36 | `to != 0` (`PayToZero`) | transfer + `PaymentSettled(from, to, amount, feeAmount, feeRecipient, entryRef)` |
-  | `trade(address counterToken, uint256 minCounterValue, address counterparty)` | 100 | `MODE_RESTRICT_RELAYER` and `to == msg.sender` (`TradeLegNotRestricted`) | transfer `from → msg.sender` |
-  | `approve(address spender, uint256 amount)` | 68 | `value == 0`, `to == spender`, spender a contract (`ApproveCarriesValue`, `ApproveSpenderMismatch`, `SpenderNotContract`) | set allowance |
-  | other | — | `MetaTxUnknownOp(bytes4)` | — |
-
-- **Guard** ([CTR-MTX-18](#CTR-MTX-18)). Transient slot `keccak256("scaas.metatx.reentrancy.v1")`; no ticket, so a
-  guarded function cannot run as a self-call.
-- **Names** ([CTR-MTX-21](#CTR-MTX-21)). v1: `cancelMetaNonce` (direct only; it increments `metaNonce[msg.sender][batch]`;
-  no event), `metaNonce`, `metaTxDigest`.
-- **Fees** ([CTR-MTX-20](#CTR-MTX-20), [CTR-MTX-08](#CTR-MTX-08)). v1: `FIXED` is capped at 1 % of `value` on every
-  public op; no `FeeRecipientIsPayee`.
-- **Clone safety** (unchanged in the target, now on every kind, [token-wrappers.md](token-wrappers.md#permissionless-vs-controlled)).
-  The implementation's `constructor(address factory_)` sets `FACTORY` and `_SELF` and locks the implementation;
-  `initialize(creator, underlying, verifier, version, initData)` does `require(msg.sender == FACTORY)` once, requires
-  `verifier == 0` (kind `META`) and runs in the same factory function as `CREATE2`; `name()`, `symbol()`,
-  `decimals()` read the clone's storage; no `pause`, blacklist, freeze, owner or upgrade.
-- **Tests** (replaced by the conformance list above). `MetaToken.t.sol`, `OpenFactory.t.sol`, `MetaTxDex.t.sol` (a fee
-  to `feeRecipient ∈ {0, dex}` reverts), the v1 KAT `test/vectors/metatx_v1_kat.json`.
+The v1 line — the `ERC20MetaTxV1` mixin, `MetaToken`, `HederaMetaToken`, factory v1, `MetaTxDex` — left the build in P5
+(`smartcontracts/evm/legacy/p5/`; owner: backup, not delete) with its tests: the 11-field `LegacyMetaTransaction`
+(vector `metatx_v1_kat.json`), the unsalted domain `("SCaaS MetaToken", "1", chainId, clone)`, `executeMetaTransaction`
+with the hand-written op dispatch (`pay`, `trade`, `approve`, `unwrap`), `cancelMetaNonce` / `metaNonce` /
+`metaTxDigest`, the guard slot without a ticket, the 1 % cap on `FIXED`, and `initialize(creator, underlying, verifier,
+version, initData)` of kind `META`. `SigCheck` serves every live base; `SigLib` is deleted. Below, how the token tree
+was built (P1b–P1d).
+
 - **Removed with the legacy v2 pipeline (P1b).** `executeMetaTransactionWithFee`, `mtxUnwrap` and `mtxUnwrapWithFee`
   (gasless unwrap is `mtxExecute(unwrap…)`); the v2 domain `name = "SCaaS MetaToken"` with `eip712Domain().version == "2"`
   (now version 1 plus the salt); its note "At most once through `mtxPay` holds per path" ([CTR-MTX-10](#CTR-MTX-10)
diff --git a/docs/contracts/token-wrappers.md b/docs/contracts/token-wrappers.md
index f103101..a3a33dc 100644
--- a/docs/contracts/token-wrappers.md
+++ b/docs/contracts/token-wrappers.md
@@ -564,8 +564,7 @@ check was dropped); the rule handles each one explicitly:
 - EVM `ERC20MetaTx` (the root of every token): `approve` reverts `CallerNotContract(caller)` for an EOA caller and
   `SpenderNotContract(spender)` for an EOA spender; `transferFrom` reverts `CallerNotContract(caller)` **before** the
   allowance check. No `permit`, no `increaseAllowance`, no meta-tx `approve`. Errors: `SpenderNotContract(address)`,
-  `CallerNotContract(address)`. **Transitional (BUILT):** the rule is built on the v2 tokens (P1b); EOA `approve` and the meta-tx
-  `approve` op remain only on the v1 line (`…V1`, until P3/P5).
+  `CallerNotContract(address)`. Built on every kind (P1b); the v1 line with its EOA `approve` is in `legacy/p5/` (P5).
 - Contract accounts approve through **their own call path**: `SmartKeyAccount.mtxExecuteAsOwner → execute(token,
   approve)`, a Safe `execTransaction`, or a Safe MultiSend that approves and uses the allowance in one transaction. The
   token sees `msg.sender` = the account. A signature check (`isValidSignature`) is not the account's execution policy
@@ -612,7 +611,7 @@ empty output — with no symptom until someone has deposited funds.
   in the constructor.
 - **Zether gate**: `zetherEnabled` default `false`; enabling and creating Zether tokens revert outside chain ids
   31337/1337 (`ZetherSafety`, [CTR-ZTH-02](zether.md#CTR-ZTH-02)). Built on `OpenFactory` (P3), with the verifier check;
-  `OpenFactoryV1` keeps its own until the v1 line moves (P5).
+  `OpenFactoryV1` (with its own) is in `legacy/p5/` (P5).
 - **Registrar** is an EOA by default (deployer); it must become a multisig before mainnet. Its only powers are
   `registerImplementation`, `deprecate`, and `setZetherEnabled`.
 - **Same rule on every family**: a fix to an Aptos package, Sui package, Solana program, Cosmos contract, TON or
@@ -681,8 +680,7 @@ struct DexConfig { address admin; uint32 relayerSharePpm; address treasury; bool
   ([CTR-DEX-24](dex.md#CTR-DEX-24)).
 - **Registry views:** `isToken`, `versionOf`; for a DEX `isDex`, `dexVersionOf` (advisory, tokens never consult them,
   [CTR-DEX-24](dex.md#CTR-DEX-24)); catalogue `registerDexImplementation`, `dexImplementationOf`, `latestDexVersion`.
-- One `IOpenFactory` and one `IFactoryToken` (the v2 interfaces are gone; the v1 ones are `IOpenFactoryV1` and
-  `IFactoryTokenV1`).
+- One `IOpenFactory` and one `IFactoryToken` (the v1 and v2 interfaces are in `legacy/`).
 
 Flag validation is the token's ([CTR-TOK-22](#CTR-TOK-22)): the factory only forwards `features`, `lockedFeatures`
 and `roles`.
@@ -695,8 +693,8 @@ and `roles`.
 built as [CTR-TOK-03](#CTR-TOK-03) and [CTR-TOK-25](#CTR-TOK-25) specify, the Zether gate and kinds 2–3 included (P3);
 `createDex` and the DEX catalogue are built (P2b-1, [CTR-DEX-24](dex.md#CTR-DEX-24)). Every kind implements
 `initialize(creator, version, TokenConfig)` and a constant `kind()`. The v1 line (`ERC20MetaTxV1`, `MetaToken`,
-`HederaMetaToken`, `MetaTxDex`) stays as `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1` (`createMetaToken`) until the node and
-clientkeys move (P5); it then goes to `smartcontracts/evm/legacy/`, not deleted (controller ruling, pending the owner).
+`HederaMetaToken`, `MetaTxDex`, `OpenFactoryV1` with `createMetaToken`) went to `smartcontracts/evm/legacy/p5/` once the
+node and clientkeys moved (P5), not deleted.
 Factory v2 is backed up in `smartcontracts/evm/legacy/p1e/` (not built).
 
 - `constructor(address registrar, bytes32 chainUid)`, `chainUid` non-zero (`ChainUidZero`). `registerImplementation` and
@@ -717,7 +715,7 @@ Factory v2 is backed up in `smartcontracts/evm/legacy/p1e/` (not built).
   `underlyings()`), `getWrapperCount/At`, `deployCountFor/deployedFor`. Every leg is indexed, `address(0)` for the
   native coin.
 - **Zether creation (BUILT, P3).** `createToken` / `createTokenUnregistered` of kinds 2–3 check `cfg.conf.verifier` (`_checkZether`)
-  as `OpenFactoryV1.createZetherToken` / `createUnregistered(ZETHER)` do: zero reverts `VerifierRequiredForZether`; no code, or
+  as `OpenFactoryV1.createZetherToken` / `createUnregistered(ZETHER)` did: zero reverts `VerifierRequiredForZether`; no code, or
   `verifier.isSupportedOnThisChain()` false or unanswered, reverts `VerifierUnsupportedOnThisChain(verifier, curveName)`
   with the verifier's `curveName()` (empty when it has no code or no answer), so a BLS12-381 verifier cannot be paired
   with a chain without EIP-2537; the token's `initialize` repeats the dev-chain check.
@@ -898,7 +896,7 @@ Unit (forge, `test/v2/`):
 
 | Area | Tests |
 |---|---|
-| Base | both typehashes pinned (`test_metaTxTypehashIsPinned`, `test_metaTransferTypehashIsPinned`, [CTR-MTX-15](metatx.md#CTR-MTX-15)); salted-domain KATs `test/vectors/metatx_kat.json` (v3 `MetaTransaction`, `MetaTxBase`; the built v1 struct is `metatx_v1_kat.json`, read by scaas-node and clientkeys until P5) and `metatransfer_kat.json` plus an `mtxpay` vector with `batch = payLane(payId)`, `nonce = 0` and `mtxExecute` calldata vectors per allowlisted selector, all checked by Solidity, node and the client library (its lane derivation already equals `payLane`); `MetaNonceCancelled`; the allowance rule on every kind (EOA caller and EOA spender of `approve` refused); ERC-1271 400 k only for `SmartKeyAccount` clones; `chainUid()` equals the implementation's; the factory refuses an implementation with another `chainUid()` |
+| Base | both typehashes pinned (`test_metaTxTypehashIsPinned`, `test_metaTransferTypehashIsPinned`, [CTR-MTX-15](metatx.md#CTR-MTX-15)); salted-domain KATs `test/vectors/metatx_kat.json` (v3 `MetaTransaction`, `MetaTxBase`; with the relayed calldata, P5; the v1 vector is in `legacy/p5/`) and `metatransfer_kat.json` plus an `mtxpay` vector with `batch = payLane(payId)`, `nonce = 0` and `mtxExecute` calldata vectors per allowlisted selector, all checked by Solidity, node and the client library (its lane derivation already equals `payLane`); `MetaNonceCancelled`; the allowance rule on every kind (EOA caller and EOA spender of `approve` refused); ERC-1271 400 k only for `SmartKeyAccount` clones; `chainUid()` equals the implementation's; the factory refuses an implementation with another `chainUid()` |
 | Fees | percent on the basis, fee on top, 1 % cap on transfer, payment and `AMOUNT` selectors; `ABSOLUTE` selectors uncapped and `PERCENT` refused; `FeeRecipientIsPayee` for transfer, `pay`, `payWithFee`, bound and relayer-default |
 | Gasless unwrap and wrap | `mtxExecute(unwrap(…))`: fee in wrapped units after the call; `UnwrapRecipientInvalid` for 0 and `address(this)`; `UnwrapBelowMin`; underlying revert (blacklist mock) reverts fee and nonce; sender-pays fee-on-transfer ⇒ `UnderlyingTransferMismatch`; ERC-777 mock whose hook re-enters (`cancelNonce`, `transfer`) mid-unwrap ⇒ `Reentrancy`; not allowlisted on tier 1; works on a disabled leg and during a pending rate change. `mtxExecute(wrap(…))` pays its fee from minted units. `mtxWrap` on `WrappedToken` (built, P2a; `WRAPPED_ZETHER` P3): price, minimum, fee to the relayer, `WrapReceivedMismatch`, unknown underlying refused |
 | Named | `testFuzz_namedDigestEqualsGeneric` over random struct fields for every named function; a signature consumed by a named call fails on the generic path and vice versa; every `MtxModeShape` case; a no-fee struct signed with a leftover `fee ≠ 0` fails through `mtxTransfer`; `mtxPay` lane equals `payLane`; second `mtxPay` of a `payId` reverts `MetaTxBadNonce`; `payWithFee` with the same `entryRef` still emits `PaymentSettled` (documents the per-path limit); `mtxBatch` atomic (one bad item reverts all), length mismatch, empty |
diff --git a/docs/history/dropped-artifacts.tsv b/docs/history/dropped-artifacts.tsv
index 83bc164..3562e75 100644
--- a/docs/history/dropped-artifacts.tsv
+++ b/docs/history/dropped-artifacts.tsv
@@ -838,3 +838,158 @@ scaas-account.__check_auth	renamed	`SmartKeyAccount.__check_auth`, networks/soro
 ownerNonce	removed	the owner call is a MetaTransaction lane 0 (P4), networks/hedera.md#NET-HED-03
 subjectAccountFactory	renamed	`smartKeyAccountFactory` (P4), clients/app.md
 bundle = u ‖ v_t ‖ v_a ‖ toUA	renamed	the PQZ bundle gains the build salt: `R = salt ‖ u ‖ v_t ‖ v_a ‖ toUA`, contracts/pq-zero-knowledge.md#CTR-PQZ-23
+HederaMetaToken.sol:22-24	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+IERC20Metadata(underlying).decimals()	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+unwrap(amount, recipient)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+Σ balance == totalSupply	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+underlying.balanceOf(this) >= totalSupply	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+constructor(address factory_)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+require(msg.sender == FACTORY)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+verifier == 0	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+symbol()	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+transfer(from → to, value)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+pay(bytes32 entryRef)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+to != 0	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+trade(address counterToken, uint256 minCounterValue, address counterparty)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+to == msg.sender	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+from → msg.sender	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+MetaTxUnknownOp(bytes4)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+settle(Leg a, Leg b)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+Leg = {IERC20MetaTx token; MetaTransaction m; bytes sig}	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+a.token != b.token	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+a.m.from != b.m.from	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+termsA.counterToken == b.token	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+b.m.value >= termsA.minCounterValue	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+feeMode != NONE	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+feeRecipient != 0	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+!= this	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+feeRecipient = msg.sender	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+a.m.value	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+b.m.value	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+SafeERC20.safeTransfer	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+emit TradeSettled(a.m.from, b.m.from, a.token, b.token, a.m.value, b.m.value)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+ReentrancyGuardTransient	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+b.m.value > minCounterValue	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+feeRecipient ∈ {0, dex}	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+relayer == to == msg.sender	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+counterToken	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+reserve >= totalSupply	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+MetaToken.t.sol	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+OpenFactory.t.sol	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+MetaTxDex.t.sol	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+reserve >= supply	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+HederaMetaToken is MetaToken	obsolete	HederaMetaToken (v1) moved to smartcontracts/evm/legacy/p5 (P5); Hedera runs the clone tree, networks/hedera.md
+approve(address spender,uint256)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+verifyingContract = DEX	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+nonce >= minNonce[maker]	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+unix_ms·2^20 + random20	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+block.timestamp <= expiry	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+makerFill	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+maker.sellToken	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+takerFill	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+taker.sellToken	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+try this.settleOne(m, msg.sender)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+filled = sellAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+msg.sender == DEX	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+relayer ∈ {0, sender}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+M.sellToken == T.buyToken	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+M.buyToken == T.sellToken	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+sellToken != buyToken	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+M.maker != T.maker	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+makerFill > 0	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+takerFill > 0	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+filled[h] + fill <= sellAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+filled[h] == 0 && fill == sellAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+takerFill · M.sellAmount >= makerFill · M.buyAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+makerFill · T.sellAmount >= takerFill · T.buyAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+feeOn ⇒ makerPpm <= M.maxFeePpm && takerPpm <= T.maxFeePpm	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+transferFrom(payer → payee)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+makerFill − takerDexFee	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+takerDexFee = makerFill · takerPpm / 1e6	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+takerFill − makerDexFee	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+makerDexFee = takerFill · makerPpm / 1e6	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+emit OrderFilled(ref, hash, owner, Fill)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+emit Matched(ref, makerHash, takerHash)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+takerFill = ceil(makerFill · M.buy / M.sell)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+cancel(CancelReq[] reqs)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+CancelReq = {Order order; bytes sig}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+CancelOrder(hash(o))	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+filled[h] = o.sellAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+invalidateNonces(maker, minNonce, sig)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+<= 2^128 − 1	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+type(uint128).max	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+setMarket(base, quote, listed, feeOn, makerPpm, takerPpm, feeRecipient)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+FeePolicy.MAX_FEE_PPM	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+feeOn	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+feeRecipient ∉ {0, DEX}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+feeToken ∈ {0, sellToken}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+FeePolicy.compute(PERCENT, fill, fee)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+fee · fill / sellAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+fee <= 1 % · sellAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+FeePolicy.compute(FIXED, sellAmount, fee)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+feeRecipient = DEX	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+BAD_FEE	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+fundable = min(balanceOf, allowance(DEX))	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+feeFundable	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+MetaToken.sol:141-143	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+data = approve(address spender,uint256 amount)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+m.value == 0	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+m.to == spender	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+_approve(from, spender, amount)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+test_approveOpRelayerFeeIsCappedToZero	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+keccak("scaas.dex.approve" ‖ rand)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+filled[h] <= sellAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+received + fee == fill	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+venue.rs:188-196	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+dex.rs:637-643	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+dex.rs:449-462	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+feeToken ∈ {0, sellToken, buyToken}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+venue.rs:317-324	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+cancel(...)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+{chain, order, signature}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+{hash, status: resting/partial/filled/cancelled, fills[]}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+{chain, orderHash, validUntil, signature}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+{chain, maker, minNonce, validUntil, signature}	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+test/vectors/dex_kat.json	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+eth_call settleOne(m, relayer)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+SafeERC20FailedOperation(token)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+venue.rs:500, 542	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+fill * ppm / PPM	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+ppm > 0	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+Math.mulDiv(fill, ppm, PPM, Math.Rounding.Ceil)	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+ppm ≤ MAX_FEE_PPM	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+dex.rs:565, 616-624	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+ppm = 3_000	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+fee ≤ fill	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+fee · PPM ≥ fill · ppm	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+feeOn = false	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+test_feeOnSplitsReceivedAmountsWithoutDust	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+smartcontracts/evm/src/hedera/HederaMetaToken.sol	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+smartcontracts/evm/script/hedera/HederaSmoke.sol	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+filled + fill ≤ sellAmount	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+try settleOne	obsolete	SCaaSDexV1 / v1 venue design, moved to legacy/p5 (P5); the DEX is contracts/dex.md, the venue node/dex-venue.md
+dex/venue.rs:1	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+dex/venue.rs:179-199	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+dex/venue.rs:403-421	internal-path	v1 file or line of the superseded v1 line; the v1 sources and tests are in smartcontracts/evm/legacy/p5 and scaas-node/legacy/p5 (P5)
+contracts.factoryV1	obsolete	v1/v2 factory deploy keys left the deploy in P5; the deploy JSON keys are networks/evm.md#NET-EVM-05
+factory_v2	obsolete	v1/v2 factory deploy keys left the deploy in P5; the deploy JSON keys are networks/evm.md#NET-EVM-05
+contracts.factoryV2	obsolete	v1/v2 factory deploy keys left the deploy in P5; the deploy JSON keys are networks/evm.md#NET-EVM-05
+subject_account_factory	obsolete	v1/v2 factory deploy keys left the deploy in P5; the deploy JSON keys are networks/evm.md#NET-EVM-05
+ (100 bytes, 	obsolete	v2 MetaTransaction(to, value) superseded by the v3 MetaTransaction/MetaTransfer (P5 removed the v1/v2 restatement), contracts/metatx.md
+m.to == recipient	obsolete	v2 MetaTransaction(to, value) superseded by the v3 MetaTransaction/MetaTransfer (P5 removed the v1/v2 restatement), contracts/metatx.md
+keccak256("scaas.metatx.reentrancy.v1")	obsolete	v2 MetaTransaction(to, value) superseded by the v3 MetaTransaction/MetaTransfer (P5 removed the v1/v2 restatement), contracts/metatx.md
+m.nonce == metaNonce(from, batch)	obsolete	v2 MetaTransaction(to, value) superseded by the v3 MetaTransaction/MetaTransfer (P5 removed the v1/v2 restatement), contracts/metatx.md
+to == spender	obsolete	v2 MetaTransaction(to, value) superseded by the v3 MetaTransaction/MetaTransfer (P5 removed the v1/v2 restatement), contracts/metatx.md
+unwrap(address underlying, address recipient, uint256 minOut)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+executeMetaTransaction(m, signature)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+PaymentSettled(from, to, amount, feeAmount, feeRecipient, entryRef)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+TradeLegNotRestricted	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+approve(address spender, uint256 amount)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+metaNonce[msg.sender][batch]	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+WrapperHasNoMint	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+NotAWrapper	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+ApproveCarriesValue	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+ApproveSpenderMismatch	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+settle(Match[]) returns (bool[])	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+cancel(CancelReq[])	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
+invalidateNonces(maker, newMin, sig)	obsolete	v1 MetaToken / MetaTxDex / OpenFactoryV1 line, moved to smartcontracts/evm/legacy/p5 (P5); current contracts/token-wrappers.md, contracts/dex.md, contracts/metatx.md
diff --git a/docs/networks/evm.md b/docs/networks/evm.md
index 97bf751..99ac063 100644
--- a/docs/networks/evm.md
+++ b/docs/networks/evm.md
@@ -171,13 +171,13 @@ block 0's hash; past block 256 `CHAIN_UID` is required). The script stops when t
 chain, deploy it first (the keyless presigned deployment transaction of that proxy, funded by a transfer to its signer)
 and re-run. `forge script … --broadcast` needs `--sender <deployer address>`, which `deploy.sh` and the e2e pass; forge
 places the linked libraries from that sender, not by CREATE2. It deploys `OpenFactory` with `NormalToken` as
-version 1 of `NORMAL` (`WrappedToken` is over EIP-170 and is not deployed until the size work) and, for the node until
-P5, the v1 line (`OpenFactoryV1` with `MetaToken` as version 1 of `META`, `MetaTxDex`), `SmartKeyAccountFactory` (P4) and
-`SCaaSDexV1` (plus the `SCaaSDex` implementation, registered as DEX version 1 on the factory), optionally a tier-1 demo token ([deploy](../contracts/README.md#build-ci-and-pins)).
+version 1 of `NORMAL` (`WrappedToken` is over EIP-170 and is not deployed until the size work), the `SCaaSDex`
+implementation as DEX version 1 (a DEX is a `createDex` clone) and `SmartKeyAccountFactory` (P4); with `DEMO_SUPPLY`, two
+kind-`NORMAL` demo tokens; the v1 line left the deploy in P5 (`legacy/p5/`) ([deploy](../contracts/README.md#build-ci-and-pins)).
 
 It writes
-`deployments/<chainid>.json` (`factory`, `implementation`, `dex`, `smart_key_account_factory`,
-`smart_key_account_implementation` (were `subject_account_*` before P4), `scaas_dex`, `demo_token`, and `token_factory`, `implementation_normal`, `dex_implementation`, `chain_uid`),
+`deployments/<chainid>.json` (`token_factory`, `implementation_normal`, `dex_implementation`, `chain_uid`, `smart_key_account_factory`,
+`smart_key_account_implementation`, `demo_token`, `demo_token_2`; `factory`, `implementation`, `dex`, `scaas_dex` are gone with v1),
 which seeds the client and the node configuration. forge writes it during the simulation, before the broadcast; `deploy.sh` puts the previous file back (or removes the new one) when the broadcast fails.
 Zether (built, P3; dev chains only, UNAUDITED): opt in with `DEPLOY_ZETHER=1` (default off, so a plain anvil deploys as before P3, every contract under EIP-170; on a non-dev chain the script refuses). It adds the account registry, `ZetherDisclosure`, `ZetherStatements`, both verifiers and the two confidential implementations (versions 1 of `NORMAL_ZETHER` and `WRAPPED_ZETHER`, the factory's Zether gate on when the deployer is the registrar), and the keys `zether_registry`, `zether_disclosure`, `zether_statements`, `zether_verifier_bn254`, `zether_verifier_bls12381`, `implementation_normal_zether`, `implementation_wrapped_zether`. The implementations exceed 24,576 B and the BLS verifier's deploy uses ~14.1 M gas (forge's estimate ~15.0 M), so `deploy.sh` then passes `--code-size-limit 65536 --gas-estimate-multiplier 105` to `forge script` (the default ×1.30 exceeds the Osaka per-transaction cap of 16,777,216, EIP-7825; ×1.13 or more fails) and the anvil needs `--code-size-limit 65536`; `ZetherDeploy.t` checks each deploy fits.
 Integration tests use `anvil --hardfork osaka --gas-limit 16777216 --code-size-limit 65536` (64 KiB code, as EIP-7954 proposes; owner 2026-10-11 — real chains keep 24,576, so a contract that only fits this anvil still cannot be deployed there).
diff --git a/docs/networks/hedera.md b/docs/networks/hedera.md
index ed5d65e..04857f9 100644
--- a/docs/networks/hedera.md
+++ b/docs/networks/hedera.md
@@ -21,8 +21,8 @@ Common rules for every family: [networks/README](README.md). Status: contracts,
 <a id="overview"></a><a id="NET-HED-04"></a>**NET-HED-04** — **Hedera is the EVM family on the Hedera Smart Contract
 Service: the same Solidity contracts behind a Hedera JSON-RPC relay, plus HIP-632 for ED25519 accounts; the
 payer-sponsored path is not used.** HSCS runs EVM bytecode (Besu), so the Solidity set is reused unchanged:
-`MetaToken` (contract-level EIP-712 meta-tx), `MandateWallet`, `MetaTxDex`/`SCaaSDexV1`. There is **no
-`SmartKeyAccount` and no EVM pipeline on Hedera** (as built: `HederaMetaToken.sol:22-24`, `adapters/hedera.rs:4-6`): native Hedera accounts already rotate keys, and the relayer runs
+the token kinds with `IS_HEDERA`, `HederaMandateWallet`, `SCaaSDex` (P5; the v1 line is in `legacy/p5/`). There is **no
+`SmartKeyAccount` and no EVM pipeline on Hedera** (as built: `DeployHedera.s.sol`, `adapters/hedera.rs:4-6`): native Hedera accounts already rotate keys, and the relayer runs
 the one-transaction-per-lane runner ([NET-HED-08](#NET-HED-08)). ED25519 accounts need a raw signer
 ([NET-HED-15](#NET-HED-15)). Payer-account sponsorship (the subject sends a Hedera account transaction whose fee
 someone else pays) is **not** used: it orders operations by the subject's account, exactly the lock
@@ -31,10 +31,10 @@ someone else pays) is **not** used: it orders operations by the subject's accoun
 
 | Piece | Hedera-specific part | File |
 |---|---|---|
-| Token | `HederaMetaToken is MetaToken`: a Hedera account's **ED25519** signature verified through HIP-632 `isAuthorizedRaw` (`0x16a`); `WrappedToken` on HTS tokens ([wrappers](#wrappers)) | `smartcontracts/evm/src/hedera/HederaMetaToken.sol` (v1), `HederaLib.sol` (v2) |
+| Token | every kind with `IS_HEDERA`: a Hedera account's **ED25519** signature verified through HIP-632 `isAuthorizedRaw` (`0x16a`); `WrappedToken` on HTS tokens ([wrappers](#wrappers)) | `smartcontracts/evm/src/hedera/HederaLib.sol` (v1 `HederaMetaToken` in `legacy/p5/`) |
 | Account auth | library calling `isAuthorizedRaw` with `CALL` (100 000 gas cap); a revert or garbage ⇒ `false` | `smartcontracts/evm/src/hedera/HederaAccountAuth.sol` |
 | Mandate | `HederaMandateWallet is MandateWallet` checks HIP-632 signatures on every entry ([NET-HED-03](#NET-HED-03)) | `smartcontracts/evm/src/hedera/HederaMandateWallet.sol` |
-| DEX | unchanged — every leg is a meta-tx on the token, so an ED25519 leg goes through `HederaMetaToken` (target: a `TradeOrder` verified by the Hedera token's signature check, [Mandate and DEX](#mandate)) | — |
+| DEX | a SCaaS leg's `TradeOrder` is checked by the Hedera token (HIP-632 included); `DexOrder` and DEX cancels have no HIP-632 branch ([Mandate and DEX](#mandate)) | — |
 | Relayer | EVM adapter pointed at the JSON-RPC relay, run under `lane_runner`; fee `eth_gasPrice × 1.2`, priority 0 | `scaas-node/src/adapters/hedera.rs` |
 | Client | long-zero payer `0.0.N` ⇒ native ED25519 path ([client families](../integration.md#families)) | — |
 
@@ -42,9 +42,9 @@ someone else pays) is **not** used: it orders operations by the subject's accoun
 
 <a id="payload"></a>
 
-On Hedera the `MetaOp` v1 **is** the EIP-712 `MetaTransaction` of `MetaToken` — there is no second format:
+On Hedera the `MetaOp` v1 **is** the token's EIP-712 `MetaTransfer` (P5; salted domain) — there is no second format:
 
-| `MetaOp` v1 | EIP-712 (`MetaToken`) |
+| `MetaOp` v1 | EIP-712 (`MetaTransfer`) |
 |---|---|
 | `domain="scaas.metaop.v1"` | `EIP712Domain{name:"SCaaS MetaToken", version:"1"}` |
 | `network` | `chainId` = 295 / 296 / 297 / 298 |
@@ -66,7 +66,7 @@ assumed); an unstable value keeps the profile `draft`.
 Cross-network replay: `chainId` in the domain (Hedera mainnet 295 differs from every other EVM chain). Cross-contract:
 `verifyingContract`. Cross-use: the token's own `(from, batch) → nonce`. Expiry: `validUntil` against
 `block.timestamp` (Hedera consensus seconds). Digest = `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`; the
-client, Solidity (`metaTxDigest`) and Rust (`metatx::digest`) compute the same value against the shared vectors
+client, Solidity (`mtxTransferDigest`) and Rust (`Mtx::digest`) compute the same value against the shared vectors
 `smartcontracts/evm/test/vectors/hedera_kat.json`.
 
 ## 3. Signatures
@@ -79,9 +79,9 @@ client, Solidity (`metaTxDigest`) and Rust (`metatx::digest`) compute the same v
 | Hedera account with a **single ED25519** key (seed key `m/44'/3030'/0'/0'/i'`) | long-zero `0x000…N` (= `0.0.N`) | **64 bytes** ed25519 over **exactly the 32-byte digest** | HIP-632 `isAuthorizedRaw(from, digest, sig)` |
 | Smart account (wallet contract) | contract address | the account's blob | ERC-1271 |
 
-<a id="NET-HED-09"></a>**NET-HED-09** — **`HederaMetaToken` verifies a 64-byte signature from an account without code
-through HIP-632 `isAuthorizedRaw`; a precompile revert means "not authorised"; everything else is `MetaToken`.**
-Branching in `HederaMetaToken._requireValidSignature`: `from` has code ⇒ ERC-1271 (unchanged); no code **and** exactly 64 bytes ⇒
+<a id="NET-HED-09"></a>**NET-HED-09** — **A token with `IS_HEDERA` verifies a 64-byte signature from an account without code
+through HIP-632 `isAuthorizedRaw`; a precompile revert means "not authorised"; everything else is the common check.**
+Branching in `MetaTokenBase._requireValidSignature` (as in v1 `HederaMetaToken`): `from` has code ⇒ ERC-1271; no code **and** exactly 64 bytes ⇒
 HIP-632; otherwise the parent's `ecrecover`. The length is unambiguous: OZ 5.2 `ECDSA.tryRecover(bytes)` accepts
 only 65 bytes (no EIP-2098), so 64 bytes are never ECDSA here, and the precompile itself classifies by length (65–72
 = EC, 64 = ED). Key ↔ account is bound **on chain** by the precompile (it reads the account's key from Hedera state),
@@ -275,9 +275,7 @@ The owner's raw call is relayed as a `call` job (selector in the call table,
 ED25519 owner sets the mandate and pays by hand (`token.pay…` inside the owner call), an ED25519 delegate pays and revokes, and the owner works through the batch and the alias; a meta-tx with
 `from = wallet` fails ERC-1271. BUILT.
 
-DEX: `MetaTxDex` and `SCaaSDexV1` are unchanged; each leg is `executeMetaTransaction` on the token, so an ED25519
-leg is verified by `HederaMetaToken`. Fees, `filled[orderHash]` and cancel as in [contracts/dex](../contracts/dex.md).
-Target (SPECIFIED): `MetaTxDex` is deleted; `SCaaSDex.mtxSettle` pulls each SCaaS leg through the sell token's
+DEX (BUILT, P2b–P5; `MetaTxDex` and `SCaaSDexV1` are in `legacy/p5/`): `SCaaSDex.mtxSettle` pulls each SCaaS leg through the sell token's
 `mtxTrade`, whose signature check is the Hedera token's own (HIP-632 for a 64-byte ED25519 signature, ECDSA,
 ERC-1271), so an ED25519 subject trades with no allowance ([NODE-DEX-15](../node/dex-venue.md#NODE-DEX-15)). HIP-632
 signers are not contracts, so they can never call `approve` on a SCaaS token
@@ -366,8 +364,8 @@ the proof is independent of the signing key.
 - **Results (2026-10-03):** forge 24 Hedera tests (157 overall) green; client verifier suite 118 tests green (4 Hedera); Rust
   9 adapter tests (including proptests of 2 × 2 000 cases) + `e2e_hedera` green (anvil 298, port 31960); connector
   `node --test` 4 green — a Node.js ed25519 signature equals the Python one byte for byte on the shared vector.
-- **Smoke on real Hedera EVM without an account or HBAR** (`smartcontracts/evm/script/hedera/HederaSmoke.sol` +
-  `testnet_smoke.py`): constructors run as initcode through `eth_call` on the testnet relay (the mirror node's web3
+- **Smoke on real Hedera EVM without an account or HBAR** (v1, `legacy/p5/script/hedera/HederaSmoke.sol` +
+  `testnet_smoke.py`; not ported to the token tree): constructors run as initcode through `eth_call` on the testnet relay (the mirror node's web3
   runs the services' EVM library and system contracts). Result 2026-10-03: `OpenFactory` + `HederaMetaToken` + clone
   deploy (TSTORE/MCOPY available); an ECDSA meta-tx payment ⇒ `ok`, the shop receives 100; a wrong ED25519 signature
   for the real ED25519 account `0.0.6000019` through the real `0x16a` ⇒ `MetaTxBadSignature`; a non-existent account
diff --git a/docs/node/README.md b/docs/node/README.md
index e41600b..d6cbc26 100644
--- a/docs/node/README.md
+++ b/docs/node/README.md
@@ -398,6 +398,6 @@ legacy pull path to the store ([job-api.md#legacy-pull](job-api.md#legacy-pull))
 | Job builder | `job.rs` `build(&Job, …)` | unchanged |
 | Keys in one process | relay and indexer keys both loaded (`main.rs:103, 117`) | [threat-model.md#node](threat-model.md#node) T7 |
 | Mesh | `mesh/digest.rs:130-300` (`check_evm`, `:193-195`), `mesh/store.rs`, e2e `tests/e2e.rs`, `tests/e2e_<family>.rs`; adapters `adapters/cosmos.rs`, `adapters/hedera.rs`; wiring `main.rs` | [mesh.md](mesh.md) |
-| DEX venue | `dex/venue.rs:1`, `dex/venue.rs:179-199`, `dex/venue.rs:403-421`, `venue.rs:188-196`, `venue.rs:317-324`, `venue.rs:500, 542`, matching `dex.rs:637-643`, watcher in `indexer.rs`; contract `SCaaSDexV1.sol:383-385` (`_validSig`: ECDSA or ERC-1271), tests `SCaaSDexV1.t.sol:555`, `SCaaSDexV1Invariant.t.sol` | [dex-venue.md](dex-venue.md) |
-| Meta-tx contracts | `smartcontracts/src/common/MetaTxLib.sol`, `ERC20MetaTx.sol`, `smartcontracts/src/metatx/ERC20MetaTx.sol`, `smartcontracts/src/hedera/HederaMetaToken.sol` | [contracts/metatx.md](../contracts/metatx.md) |
+| DEX venue | book and matcher `dex.rs` (`Book::matching`, `settlement_ok`), I/O `dex/venue.rs` (intake reads, `mtxSettle` simulation and attribution, sync, watcher); contract `SCaaSDex.sol` (P2b–P2c); the `SCaaSDexV1` venue in `scaas-node/legacy/p5/` | [dex-venue.md](dex-venue.md) |
+| Meta-tx path and guard | `abi.rs`, `metatx.rs` (both structs, salted digests), `guard.rs` (call table, `chainUid()`, selector table, gas); contracts `MetaTxLib.sol`, `MetaTxBase.sol`, `ERC20MetaTx.sol`; the v1 line in `legacy/p5/` | [contracts/metatx.md](../contracts/metatx.md) |
 | Console app | `scaas/app/` | [clients/app.md](../clients/app.md) |
diff --git a/docs/node/dex-venue.md b/docs/node/dex-venue.md
index 49bca08..7c13053 100644
--- a/docs/node/dex-venue.md
+++ b/docs/node/dex-venue.md
@@ -1,11 +1,11 @@
 # DEX venue
 
-The DEX venue is the node's off-chain order book in front of `SCaaSDexV1` until P5, then `SCaaSDex` ([contracts/dex.md](../contracts/dex.md)):
+The DEX venue is the node's off-chain order book in front of a `SCaaSDex` clone ([contracts/dex.md](../contracts/dex.md)):
 it admits signed orders at the gateway, matches them price-time, and settles each match — one taker against one or
 more makers — with `mtxSettle` jobs in `~dex`. The contracts are the arbiter of every fill; the venue only decides
 which matches are worth sending. Status: book, matcher, intake, routes and watcher **BUILT** (book persisted in the
-legacy client; DEX-domain orders settled pair by pair); token-verified orders and `mtxSettle`
-([trade orders](#trade-orders)) **SPECIFIED**; store-backed book **SPECIFIED**; book gossip and managed markets
+legacy client); token-verified orders and `mtxSettle` ([trade orders](#trade-orders)) **BUILT** (P5); the TradeEngine
+(P7), the store-backed book **SPECIFIED**; book gossip and managed markets
 **SPECIFIED**; non-EVM books **PLANNED**.
 
 **Contents**
@@ -56,7 +56,7 @@ stored, and kept on reload (time priority survives restarts).
 
 <a id="matching"></a>Pure, no I/O. An incoming order `O` walks the opposite side in order; against a resting order `R`
 (maker) with `R.rem` left: `x = min(R.rem, floor(O.rem · R.sell / R.buy))`, `y = ceil(x · R.buy / R.sell)`; `x = 0` ⇒
-stop; check `limits_ok(R, O, x, y)` **exactly** as the contract does (including FOK); if it fails (ceiling rounding
+stop; check `limits_ok(R, O, x, y)` **exactly** as the contract does (`y` the maker's ceiling); if it fails (rounding
 pushes `y` past O's limit at tiny amounts), never emit a pair the contract would refuse. Resting orders of the same
 maker are **skipped** (self-trade prevention; the contract refuses them too).
 
@@ -68,13 +68,12 @@ dust ask at the head + a deeper ask ⇒ an incoming bid matches the deeper ask;
 
 - **GTC limit:** the remainder rests in the book.
 - **IOC:** match what can be matched, cancel the rest (never rests). On EVM the contract closes the IOC remainder at the
-  end of the `settle` tx, also across several makers; a short `expiry` (≤ 60 s) is the second layer.
-- **FOK:** checked **on chain**: a FOK order settles only in **one** pair that fills its whole `sellAmount`. The book
-  matches FOK only against a single resting order (the first by price-time) that can fill it entirely; otherwise the
-  whole order is cancelled. No aggregation of several counterparts for FOK: "all or nothing" across several pairs of a
-  pair-atomic batch is not provable on chain. Partial fill is the default for every other kind. Target: a FOK order is
-  a `TradeOrder` with `minFill = amount`, and one settlement (one taker, several makers) is atomic, so FOK **may**
-  aggregate several makers inside that settlement ([NODE-DEX-15](#NODE-DEX-15)).
+  token's pull (`pulled = amount`), whatever the makers; a short `validUntil` (≤ 60 s) is the second layer.
+- **FOK:** a `TradeOrder` with `minFill = amount`, checked **on chain** by the effective minimum fill: one settlement
+  (one taker, several makers) is atomic, so FOK aggregates the makers it crosses or settles nothing, and its remainder
+  never rests. Partial fill is the default for every other kind. A remainder that still crosses after matching (its
+  makers' minimum fills could not be met) is cancelled, never left as a locked crossed book; an order handed back that
+  may not take (signed fee under the taker rate) rests. Built (P5), [NODE-DEX-15](#NODE-DEX-15).
 - Resting orders are never FOK/IOC (they do not rest).
 
 <a id="NODE-DEX-09"></a>**NODE-DEX-09** — **IOC matches a single maker on Move and Solana.** Sui, Aptos and Solana close
@@ -82,22 +81,21 @@ an IOC at its **first** fill, so the matcher has a per-family flag `ioc_single_m
 treats IOC like FOK's single counterpart. Required before non-EVM books are served. Cargo test.
 
 <a id="NODE-DEX-07"></a>**NODE-DEX-07** — **The committed balance includes unsettled fills.** At intake, Σ
-`remaining` (+ the relayer fee in `sellToken`) of every open order of the same (maker, sellToken) **plus the new
+`remaining` of every open order of the same (maker, sellToken) **plus the new
 order**, **plus fills already matched whose trade is not yet `settled`/`failed`** (funds not yet moved but `remaining`
 already reduced) must be `<= fundable`; cleared when the trade completes. Otherwise a balance of 100 could place 50
 orders of 100. Test: balance 100, ask #1 100 matched and pending ⇒ ask #2 100 refused. (Today `Book::committed`
-counts only resting orders, `dex.rs:449-462`.)
+counts only resting orders.)
+
+The venue computes no DEX fee: the fee is each order's signed `fee` rate, charged by the DEX once per order per
+settlement on what it receives and rounded up ([CTR-DEX-11](../contracts/dex.md#CTR-DEX-11)), so `fundable` is the sold
+side alone; the venue applies its per-role rates at intake ([NODE-DEX-15](#NODE-DEX-15)).
 
-The venue computes no DEX fee: the matcher only compares the signed `maxFeePpm` with the market fee; the DEX fee is
-taken from the transferred amount (so `fundable` is unchanged) and rounds up per fill on chain
-([CTR-DEX-11](../contracts/dex.md#CTR-DEX-11)). This is the built behaviour; with token-verified orders the fee is the
-order's signed `fee` rate, charged once per order per settlement on what it receives, and the venue applies its
-per-role rates at intake ([NODE-DEX-15](#NODE-DEX-15)).
 
 ## 3. Token-verified orders
 
 <a id="trade-orders"></a><a id="NODE-DEX-15"></a>**NODE-DEX-15** — **The venue settles role-free `TradeOrder`s with
-`mtxSettle`, one taker against one or more makers, and arranges the roles itself.** Status: **SPECIFIED**. The
+`mtxSettle`, one taker against one or more makers, and arranges the roles itself.** Status: **BUILT** (P5). The
 contract side — the struct, the token's checks, the DEX's payout and conservation — is
 [contracts/dex.md](../contracts/dex.md) and [contracts/metatx.md](../contracts/metatx.md); this rule is what the venue
 does with it.
@@ -149,12 +147,12 @@ never grants one ([CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)); orde
 order rest and later take. Cost: two transfers per leg (into the DEX, out to the destination), and partial fills
 below half an order are impossible.
 
-Transitional (BUILT): the venue matches DEX-domain orders (`maker`/`taker` fields, `sellAmount`/`buyAmount`,
-`maxFeePpm`, a separate relayer fee in `feeToken`) funded by an allowance to the DEX, and settles them pair by pair
-with `settle(Match[])`; the legacy `MetaTxDex` is not served. Both go when the token-verified DEX is deployed.
+Built (P5, `dex.rs`, `dex/venue.rs`): `ESCROW` is refused at intake (Path B is not built by the venue); the gas of
+every `mtxSettle` job is sized by a simulation that settles each planned settlement (an empty `MatchFailed` is gas);
+the venue's own `SCaaSDexV1` line is in `legacy/p5/`. Not built: the per-poll market re-check (NODE-DEX-08).
 
 <a id="NODE-DEX-16"></a>**NODE-DEX-16** — **The venue serves only DEXes on the chain profile's DEX list.** Status:
-**SPECIFIED**. An order whose `dex` is not on the chain's DEX list ([NET-ALL-24](../networks/README.md#NET-ALL-24)) is
+**BUILT** (P5) for the chain's `dex` (one per chain). An order whose `dex` is not on the chain's DEX list ([NET-ALL-24](../networks/README.md#NET-ALL-24)) is
 refused at intake (`422 DEX_NOT_LISTED`), whatever the market (a listed DEX is `isDex` and of a non-deprecated version, [CTR-DEX-24](../contracts/dex.md#CTR-DEX-24)); an order for a listed DEX that this venue does not run
 is answered with that DEX's home ([gossip](#gossip)) or refused. The node never builds, simulates or submits
 `mtxSettle` for an unlisted DEX, never relays an `mtxWrap` whose wrapper is not a registered wrapper of that
@@ -192,10 +190,10 @@ the DEX depends on its honesty — clients therefore keep `relayer` = the venue
 
 ## <a id="intake"></a>5. Intake
 
-Spam controls at the door: body ≤ 64 KiB; amounts `0 < amount < 2^128`; `expiry ∈ (now + 5 s, now + 30 days]`; a
-per-market minimum (`min_base_amount`: an ask compares `sellAmount`, a bid compares `buyAmount`); at most
+Spam controls at the door: body ≤ 64 KiB; amounts `0 < amount < 2^128`; `validUntil ∈ (now + 5 s, now + 30 days]`; a
+per-market minimum (`min_base_amount`: an ask compares `amount`, a bid `receiveAmount`); at most
 `MAX_OPEN_PER_MAKER = 50` open orders per maker per chain; a whole-book cap `MAX_RESTING = 10 000`; a duplicate hash ⇒
-refused; `checkOrder` must answer `OK`; the committed-balance rule above.
+refused; the order open on chain (`pulled`, `minNonce`), its signature valid; the committed-balance rule above.
 
 - **Relayer binding**: by default (home-bound markets) an order must name this node's relayer; `relayer = 0` is refused
   at the door — an open order anyone can settle lets a mempool watcher insert its own pair at the worst price within
@@ -205,21 +203,18 @@ refused; `checkOrder` must answer `OK`; the committed-balance rule above.
 - **DEX listing**: `dex` must be on the chain's DEX list and run by this venue for the market
   ([NODE-DEX-16](#NODE-DEX-16)); a signed `fee` below the venue's rate for the order's role ⇒ `FEE_TOO_LOW`
   ([NODE-DEX-15](#NODE-DEX-15)).
-- **On-chain cancel** (costs relayer gas): only for orders in the book; batched into **one** `cancel(...)` per poll
-  (≤ 50 orders; target: one `mtxCancelOrders` call on the DEX, or a job per sell token for `mtxCancelOrder`); at most 20 on-chain cancels per maker per hour — beyond the cap the order is still removed from the
+- **On-chain cancel** (costs relayer gas): only for orders in the book, at the next poll: an `mtxCancelOrder` job per
+  SCaaS order on its sell token, one `mtxCancelOrders` call on the DEX per market (≤ 50); at most 20 on-chain cancels per maker per hour — beyond the cap the order is still removed from the
   book at once (this relayer is the only one that can settle it) but no gas is spent. Cancel-all only when the maker
   still has ≥ 1 open order.
 
 <a id="fault-attribution"></a><a id="NODE-DEX-02"></a>**NODE-DEX-02** — **Failed matches are attributed by evidence,
-and (as built) the relayer fee token is limited.** Target: an `mtxSettle` that fails in simulation is attributed from
-the `orderHash` in the token's or the DEX's error ([NODE-DEX-15](#NODE-DEX-15)); an outside token's
-`SafeERC20FailedOperation(token)` is attributed to the order that sells that token; the restore and removal rules below
-are unchanged; with no separate relayer fee there is no fee token to limit. Transitional (BUILT): intake requires `feeToken ∈ {0, sellToken, buyToken}` (the two tokens of the
-listed market); otherwise refused at the door (a fake fee token with `balanceOf`/`allowance` = 2^255 whose
-`transferFrom` always reverts would pass `checkOrder` with a huge `feeFundable` and block every taker crossing it). A pair that fails in
-simulation is attributed from the revert reason of `eth_call settleOne(m, relayer)` with `from = DEX`, never guessed: a
-DEX error carries an `orderHash`; a token error (`SafeERC20FailedOperation(token)`) is attributed to the side that pays
-that token in the pair (M pays X, T pays Y, each pays its own fee token). Only a reason that points at the new order
+and never guessed.** An `mtxSettle` settlement that fails in simulation is attributed from the revert data of
+`eth_call settleOne(s, relayer)` with `from = DEX`: an `orderHash` in it (token and DEX errors carry one,
+[NODE-DEX-15](#NODE-DEX-15)) names the order; without one, each maker's on-chain state is read (open amount, nonce,
+balance or allowance to the puller, signature) and a maker that can no longer settle is the one at fault; with no
+separate relayer fee there is no fee token to limit (`SCaaSDexV1` limited it against a fake fee token answering 2^255). Built (P5). A `SigCheckGasStarved` revert of a multi-settlement
+simulation is split and each settlement simulated alone, never retried whole with more gas (CTR-DEX-08). Only a reason that points at the new order
 answers `400`; one that points at the maker ⇒ the maker is dropped (`invalid`) and matching retries (≤ 3 rounds). A
 maker that fails in 2 pairs with 2 different takers is removed. Recovery after a failed settle (`sync_once`) uses the same
 attribution: only the side at fault is not restored.
@@ -237,9 +232,9 @@ own `Router` merged into the gateway router, so the auth layer wraps it without
 
 | Route | Does |
 |---|---|
-| `POST /v1/dex/orders` `{chain, order, signature}` | place ⇒ `{hash, status: resting/partial/filled/cancelled, fills[]}`; target: `order` is a `TradeOrder` (SCaaS sell token) or a `DexOrder` `{sellToken, order}` (outside sell token), per the DEX's listing |
-| `POST /v1/dex/cancel` `{chain, orderHash, validUntil, signature}` | `CancelOrder` signature ⇒ removed from the book **at once** + on-chain `cancel` job (target: `CancelOrder` in the sell token's domain ⇒ `mtxCancelOrder` job on that token; a `DexOrder` ⇒ DEX `mtxCancelOrders`) |
-| `POST /v1/dex/cancel-all` `{chain, maker, minNonce, validUntil, signature}` | `InvalidateNonces` ⇒ every order with `nonce < minNonce` removed + on-chain job (target: `{chain, token, from, batch, minNonce, signature}`, per sell token and order lane ⇒ `mtxInvalidateNonces`) |
+| `POST /v1/dex/orders` `{chain, sellToken, order, signature}` | place ⇒ `{order_hash, status: resting/partial/filled/cancelled, fills[]}`; `order` is a `TradeOrder`, signed in the sell token's domain (SCaaS) or as a `DexOrder` in the DEX's (outside token), per the DEX's listing |
+| `POST /v1/dex/cancel` `{chain, orderHash, signature}` | `CancelOrder` (where the order lives) ⇒ removed from the book **at once**; on chain at the next poll: `mtxCancelOrder` on the sell token, or the DEX's `mtxCancelOrders` |
+| `POST /v1/dex/cancel-all` `{chain, sellToken, from, batch, minNonce, signature}` | `InvalidateNonces` in the sell token's domain (its SCaaS orders) or the DEX's (outside tokens) ⇒ the lane's orders with `nonce < minNonce` removed + `mtxInvalidateNonces` job; already in force on chain ⇒ no job |
 | `GET /v1/dex/markets?chain` | markets + fees |
 | `GET /v1/dex/depth?chain&market&levels` | aggregated price levels of both sides (levels ≤ 200); prices are decimal strings scaled by both tokens' `decimals`, never a raw integer division |
 | `GET /v1/dex/trades?chain&market` | recent fills (ring of 200 in memory; history from the feed) |
@@ -255,9 +250,9 @@ a dependency for no need at the volumes served.
 
 <a id="watcher"></a><a id="NODE-DEX-04"></a>**NODE-DEX-04** — **The DEX watcher has its own cursor.** One task per
 chain with the same finality helpers as the indexer (`finality::{safe_head, next_range, quorum_ok}`) and a **separate
-cursor** (`dex_cursor`) reads the DEX contract's logs (`OrderFilled`, `Matched`, `MatchFailed`, `OrderCancelled`,
-`NoncesInvalidated`; target: the DEX's `LegSettled`, `ExchangeLegSettled` and the listed tokens' `TradeFilled`, `OrderCancelled`,
-`NoncesInvalidated`, [indexer-feeds.md#event-normalization](indexer-feeds.md#event-normalization)), writes `dex_range` feed items and advances `dex_cursor`, then removes from the book every order
+cursor** (`dex_cursor`) reads the DEX's `LegSettled`, `MatchFailed` (an empty reason reported `out_of_gas`), `OrderCancelled`,
+`NoncesInvalidated` and the market tokens' `OrderCancelled`, `NoncesInvalidated` (BUILT, P5; `ExchangeLegSettled` with P7,
+[indexer-feeds.md#event-normalization](indexer-feeds.md#event-normalization)), writes `dex_range` feed items and advances `dex_cursor`, then removes from the book every order
 closed on chain (cancelled through any relayer, too). `settled` is final: a later `MatchFailed` does not flip it. A
 separate cursor means a DEX ingest fault never blocks payment booking and vice versa.
 
@@ -288,10 +283,10 @@ CREATE TABLE dex_cursor (chain_key TEXT PRIMARY KEY, indexed_block BIGINT NOT NU
 
 Transitional (BUILT): the book lives in the client database. At start `dex_book_load(chain)` loads every
 `open/partial` order (signature, `remaining`, `seq`) and rebuilds price-time order; an order is matched on a **copy**
-of the book, `settle` simulated, then `dex_book_commit` (orders + trade + job) runs; only on success is the in-memory
+of the book, `mtxSettle` simulated, then `dex_book_commit` (orders + trade + job) runs; only on success is the in-memory
 book replaced. A failed commit (a timeout included: the client may have committed) reloads the whole book and answers
 `503`; `trade_ref` UNIQUE blocks double writes. A failed trade (job `dead/reverted`, or a final `MatchFailed`) is set
-`failed` by the client and the node's `dex_sync` loop restores eligible orders (IOC/FOK never). The book-location
+`failed` by the client and the node's `dex_sync` loop restores eligible orders (IOC never). The book-location
 choice (<!-- example:odoo -->first phrased "Odoo hay SQLite"<!-- /example -->) was first recorded in the DEX design note `2026-10-03-dex-design.md`; the target is the node store.
 
 Lifecycle in the venue:
@@ -299,26 +294,26 @@ Lifecycle in the venue:
 1. **Start:** `Venue::start` loads markets from the config snapshot and the book from `dex_order` (every `open/partial`
    order with its signature, `remaining` and `seq`) ⇒ rebuilds price-time order (`seq` is the time); the on-chain market
    cross-check stays.
-2. **Place:** door checks ([intake](#intake)) ⇒ match on a **copy** of the book ⇒ simulate `settle` ⇒ a pair that
-   fails in simulation: `checkOrder` both sides, the faulty order is dropped (persisted `invalid`), retry (≤ 3 rounds)
+2. **Place:** door checks ([intake](#intake)) ⇒ match on a **copy** of the book ⇒ simulate `mtxSettle` ⇒ a failing
+   settlement: the order at fault ([NODE-DEX-02](#NODE-DEX-02)) is dropped (persisted `invalid`), retry (≤ 3 rounds)
    ⇒ **one transaction** (orders upsert + trades + settle `job` INSERT in `~dex` with origin key `keccak(calldata)` +
    `feed_item(dex_order/dex_trade)` in the market's namespace) ⇒ only then replace the in-memory book. A trade tag is
    unique, so a trade is never recorded twice.
 3. **Failed trade** (settle job `dead`/`reverted`, or a final `MatchFailed`): the venue marks the trades `failed` and
-   restores fills in the same transaction. IOC/FOK orders are **never** restored (they do not rest); a regular order
-   still valid on chain (`checkOrder`) gets its `fill` back and **goes through the matcher again** with its old `seq`
+   restores fills in the same transaction. IOC orders are **never** restored (they do not rest); a regular order still
+   open and funded on chain gets its `fill` back, makers first, and **goes through the matcher again** with its old `seq`
    (time priority kept) — not inserted directly: if both sides are healthy (the job died for a relayer reason), a direct
    insert would leave a crossed book; through the matcher they match again into a **new** trade (tag salted per
    process + counter, never a replay of the old tag), simulated and committed. Otherwise the order is dropped. Orders
    cancelled on chain (also through another relayer) arrive as final `OrderCancelled/NoncesInvalidated` and are
    removed from the book.
-4. **Final:** the watcher sees `OrderFilled/Matched/MatchFailed` in a final range ⇒ trade `settled` ⇒ booked by the
+4. **Final:** the watcher sees `LegSettled`/`MatchFailed` in a final range ⇒ trade `settled` ⇒ booked by the
    client.
 
 <a id="NODE-DEX-10"></a>**NODE-DEX-10** — **A late settled trade debits a restored order.** If a trade marked
-`failed` and restored later turns out `settled` (a late `Matched` after recovery), the venue subtracts that amount from
+`failed` and restored later turns out `settled` (a late `LegSettled` after recovery), the venue subtracts that amount from
 the restored order's `remaining` on the next pass (a `dex_trade` item settled late ⇒ `remaining` reduced). Test: a late
-`Matched` after recovery ⇒ no phantom liquidity left in the book.
+`LegSettled` after recovery ⇒ no phantom liquidity left in the book.
 
 Transitional (BUILT): the book is persisted in the legacy client over the pull protocol (`dex_markets`,
 `dex_book_load`, `dex_book_commit` with a full reload on commit failure or timeout, `dex_sync` for failed trades,
@@ -329,8 +324,8 @@ through the legacy `dex_book_load`, then resumes markets in the node.
 
 <a id="gossip"></a><a id="NODE-DEX-12"></a>**NODE-DEX-12** — **DEX book gossip, two order modes per market.**
 **Home-bound** (default; `dex.rs` l.552–554): an order bound to relayer `r` is matched and settled **only by the home** that proved `r` in
-its announce ([gossip.md#announce](gossip.md#announce)); `SCaaSDexV1._accept` (`relayer ∈ {0, sender}`, l.263) makes this
-**hard**, and with `filled + fill ≤ sellAmount` (l.267) and each pair in `try settleOne` (`MatchFailed`) **no fill can be
+its announce ([gossip.md#announce](gossip.md#announce)); `TradeLib.precheck` (`relayer ∈ {0, submitter}`; `SCaaSDexV1` l.263, l.267 before P5) makes this
+**hard**, and with `pulled + fill ≤ amount` and each settlement in its own self-call (`MatchFailed`) **no fill can be
 settled twice in either mode**; the rules below only keep honest nodes from wasting gas and showing phantom fills. Other nodes keep read-only replicas — a home register (highest `home_seq` wins) joined with chain facts
 (`filled = max`, `closed = or`) — and replicate/advertise only **DEX-trusted homes**. **Relayer-unbound**
 (`dex_market.unbound = 1`, maker opts in per order with `relayer = 0`): resting GTC orders only; one deterministic
@@ -514,12 +509,12 @@ Private-profile chains: managed markets are never on gossip ([gossip.md#private-
 <a id="tests"></a>cargo: price-time matching, partial fills, IOC, FOK, match limits == contract, snapshot/reload
 (durable), spam controls, digest KAT, event decoding; dust maker at the head + deeper maker ⇒ the taker matches the
 deeper maker; a poisoned-`feeToken` maker with "healthy maker, failed pair" blocks neither other takers nor recovery;
-an OOG pair is not restored; `min_nonce < 2^(w−1)` per network (Sui/Aptos `w = 128`, Solana `w = 64`); over-commitment while a trade is pending; an on-chain market fee raise ⇒ the market stops
+an empty `MatchFailed` reported `out_of_gas`; `min_nonce < 2^(w−1)` per network (Sui/Aptos `w = 128`, Solana `w = 64`); over-commitment while a trade is pending; an on-chain market fee raise ⇒ the market stops
 being served within one poll; IOC single maker on the Move/Solana families; a late `Matched` after recovery debits the
-book. e2e (anvil ports 31950–31959, gateway 18650–18659): approve meta-tx → two orders through the gateway → partial
-match → settle job → balances; cancel ⇒ settle never runs; venue restart ⇒ book intact. Token-verified orders
-(SPECIFIED): one taker against three makers in one atomic settlement; a maker offered less than half its order is
-skipped; FOK filled across two makers; an IOC remainder never rests; an `ESCROW` taker refunded in the same call;
+book. e2e (anvil ports 31950–31959, gateway 18650–18659, a `SCaaSDex` clone): orders through the gateway, no
+allowance → partial match → `mtxSettle` job → balances, fee split; restart ⇒ book intact; cancels on the token and
+cancel-all; an outside-token `DexOrder` through the puller. Built (P5) in `dex.rs`: two makers in one settlement; a
+maker offered less than its minimum is skipped; FOK filled across two makers; an IOC remainder never rests; `ESCROW` refused;
 signed `fee` below the taker rate ⇒ `FEE_TOO_LOW`; `dex` off the chain's list ⇒ `DEX_NOT_LISTED` at intake and never
 replicated; cancel on the sell token closes the order on the mined `OrderCancelled`; the DEX's balances unchanged after
 every settlement. TradeEngine: route finder (hops, cycles), coincidence of wants, quote → plan → simulation,
diff --git a/docs/node/gateway.md b/docs/node/gateway.md
index 508a7a0..cd83fac 100644
--- a/docs/node/gateway.md
+++ b/docs/node/gateway.md
@@ -83,7 +83,7 @@ A duplicate returns `200` with the stored state (idempotent).
 | Route | Body / answer | Accept checks, in order |
 |---|---|---|
 | `GET /v1/gateway` | above | — |
-| `POST /v1/metatx {chain, token, struct?, m, signature}` (`struct` = `call` \| `transfer`, default `transfer`; [CTR-MTX-15](../contracts/metatx.md#CTR-MTX-15)) | `202 {"status":"queued"}` today; the target adds `"intent_id"` (+ `exclusive` when published on the mesh) | token registered and active (`TOKEN_NOT_SERVED`); strict parse; normalization ([NODE-LANE-10](submit-lanes.md#NODE-LANE-10)) before simulation; `data` shape and selector ([NODE-JOB-20](job-api.md#NODE-JOB-20)); `metaTxDigest` (target `mtxDigest`) + simulation; [door A rules](#door-a-intake). On Hedera chains (295–298) `sig_bytes` may be **64** bytes (HIP-632 ED25519); 65–2048 bytes elsewhere |
+| `POST /v1/metatx {chain, token, struct?, m, signature}` (`struct` = `call` \| `transfer`, default `transfer`; [CTR-MTX-15](../contracts/metatx.md#CTR-MTX-15)) | `202 {"status":"queued"}` today; the target adds `"intent_id"` (+ `exclusive` when published on the mesh) | token registered and active (`TOKEN_NOT_SERVED`); strict parse; normalization ([NODE-LANE-10](submit-lanes.md#NODE-LANE-10)) before simulation; `data` shape and selector ([NODE-JOB-20](job-api.md#NODE-JOB-20)); simulation, then `mtxDigest` / `mtxTransferDigest`; [door A rules](#door-a-intake). On Hedera chains (295–298) `sig_bytes` may be **64** bytes (HIP-632 ED25519); 65–2048 bytes elsewhere |
 | `POST /v1/ops {chain, op}` | `op` = the job API `signed_op` payload; `202 {"status": "queued", "intent_id": "<digest hex>"}` | below |
 | `POST /v1/ua-metatx {chain, token, struct?, m: WireUAMetaTransaction \| WireUAMetaTransfer, auth}` | `ua_metatx` job | token `features ∋ ua` (v3: `registry() ≠ 0`); `from >> 160 ≠ 0` ⇒ registry record ([UA record cache](#ua-cache), `UA_NOT_REGISTERED`); cheap kinds verified locally ([NODE-GSP-15](gossip.md#NODE-GSP-15)); node computes `uaDigest` |
 | `POST /v1/ua/register {chain, kind, keyData, pop, authRef}` (`{chain, kind, keyData: 0x…, pop: 0x…, authRef: 0x…32}`) | `call` job to `chain.ua_registry` ([NODE-GW-03](#NODE-GW-03)) | id recomputed, `>> 160 ≠ 0`; not registered (`UA_ALREADY_REGISTERED`, `UA_KEY_IN_USE`); PoP verified for cheap kinds over `pop_digest` with `chain.chain_uid`; per-chain registration quota |
@@ -192,9 +192,9 @@ signatures fail, and is unsafe only if it equals another chain's `chain_uid`, wh
 genesis hash excludes. Cost: one `chainUid()` read per contract at start, and one per user-deployed wallet or
 account.
 
-Transitional (BUILT): deployed tokens, the DEX, mandate wallets and subject accounts expose no `chainUid()` until
-they are redeployed with the salted domain; until then the binding covers the genesis hash and the UA registry, on
-chains with `ua_registry` only.
+Built (P5, legacy pull path): a lane does not start when the RPC's block 0 differs from `[[chains]] chain_uid` (unset:
+block 0 is the `chain_uid`); every contract a meta-transaction, order entry or `call` targets is checked at lease
+(`chainUid()`, cached once equal; a mismatch is `dead` with `CHAIN_UID_MISMATCH`). The multi-endpoint quorum is not built.
 
 ### <a id="eip-7702"></a>3.3 EIP-7702
 
diff --git a/docs/node/job-api.md b/docs/node/job-api.md
index 86b86b0..f8edda3 100644
--- a/docs/node/job-api.md
+++ b/docs/node/job-api.md
@@ -152,7 +152,7 @@ unchanged. A W3C `traceparent` header applies to every item of the batch ([NODE-
 ### 5.2 Meta-transaction data
 
 <a id="selector-table"></a><a id="NODE-JOB-20"></a>**NODE-JOB-20** — **The node reads a meta-transaction's `data`
-through the implementation's published selector allowlist.** Status: **SPECIFIED**. On EVM and Hedera every SCaaS
+through the implementation's published selector allowlist.** Status: intake **BUILT** (P5). On EVM and Hedera every SCaaS
 contract's `mtxExecute` (alias `executeMetaTransaction`) runs a **self-call** of one of the contract's own functions
 whose selector is on that implementation's fixed allowlist ([CTR-MTX-17](../contracts/metatx.md#CTR-MTX-17)); a
 token's transfers and payments are `MetaTransfer`s with no `data` to read ([CTR-MTX-23](../contracts/metatx.md#CTR-MTX-23)). The node keeps, per registered implementation, the table
@@ -181,12 +181,12 @@ token's gateway: it acts through its own contract ([NODE-JOB-19](#NODE-JOB-19)).
 operation (wrap, burn, reserve top-up, confidential funding) impossible to relay; a published per-implementation table
 keeps the node's view exact without a node release per operation. Cost: one table read per registered implementation.
 
-Transitional (BUILT): deployed tokens accept a fixed op list (`pay`, `trade`, `approve`, the `unwrap` pseudo-op; the
-confidential token adds its transfer and burn ops) and reject any other selector; the node's built intake and pricing
-decode exactly that list, and `approve` and `trade` ops are no longer accepted once the allowlist tokens replace them.
+Built (P5, `scaas-node/src/guard.rs`): before simulation, cached per contract — the selector listed, an `AMOUNT`
+selector's basis argument present, no `PERCENT` fee on an `ABSOLUTE` selector, the mode inside `supportedModes()` (the
+static length stays the contract's check). Not built: canonical re-encoding of dynamic `data`, pricing, the breaker.
 
-<a id="metatx-entries"></a>**Order and wrap entries.** Besides `mtxExecute`, three token entry points carry their own
-signature and run as `metatx` jobs, `payload.entry` naming them (default `mtxExecute`):
+<a id="metatx-entries"></a>**Order and wrap entries** (BUILT, P5). Besides `mtxExecute`, three token entry points carry their
+own signature and run as `metatx` jobs, `payload.entry` naming them (default `mtxExecute`; a deadline in `validUntil`):
 
 | `entry` | Target | Payload | Node digest (idempotency) |
 |---|---|---|---|
@@ -391,10 +391,10 @@ equals `chain.chain_uid` ([NODE-GW-07](gateway.md#NODE-GW-07)); a mismatch ⇒ `
 
 `pqz_call` jobs are not `call` jobs: their own selector list is in the kinds table above.
 
-Transitional (BUILT): the contracts are renamed (P4: `SmartKeyAccount`, `MandateWallet` on `MetaTxBase`); chains deployed
-before P4 and the node's built table use the earlier names — `SubjectAccount.executeAsOwner`, `MandateWallet.payUnderMandate`/`revokeWithSig`/`executeAsOwner`,
-`SCaaSDexV1.settle`/`cancel`/`invalidateNonces` — and the DEX row also matches the chain's single `dex` field. The
-renamed rows replace them in the release that deploys the renamed contracts; no deployed chain keeps both.
+Built (P5, `guard.rs`, every lane before simulation; refusal `dead` with `CALL_TARGET_REFUSED` on the pull path): the
+account factory, wallet and DEX rows (`mtxExecuteAsOwner` is one selector on the account and the wallet: the wallet's
+rule), the DEX rows on the chain's `dex`, each target bound (`chainUid()`). Rows whose contracts are not built (UA
+registry, tender, vesting, distribution, `ExchangeOffer`, `Safe`) are absent, so their selectors are refused.
 
 ## 12. Job states
 
diff --git a/docs/node/mesh.md b/docs/node/mesh.md
index cdf7d4f..a63b8ce 100644
--- a/docs/node/mesh.md
+++ b/docs/node/mesh.md
@@ -343,7 +343,7 @@ sender-chosen id; with id = digest the two are one value).
 
 | Family | `intent_id` = | Routing fields decoded from | Implementations that must agree |
 |---|---|---|---|
-| `evm`, `hedera` | `keccak256(0x1901 ‖ domainSeparator(name, version, chainId, contract, salt) ‖ hashStruct(canonical(m)))`; `chainId` = number in `chain_key`; `salt` = the receiver's own `chain.chain_uid`, never a value from the envelope (target; deployed tokens have no salt yet, [NODE-GW-07](gateway.md#NODE-GW-07)); a self-call `data` must be canonical before hashing ([NODE-JOB-20](job-api.md#NODE-JOB-20)) | `meta_tx` (all signed) | `MetaTxLib.hashStruct` (`smartcontracts/src/common/MetaTxLib.sol`), `metatx.rs` `digest()`, client libraries |
+| `evm`, `hedera` | `keccak256(0x1901 ‖ domainSeparator(name, version, chainId, contract, salt) ‖ hashStruct(canonical(m)))`; `chainId` = number in `chain_key`; `salt` = the receiver's own `chain.chain_uid`, never a value from the envelope ([NODE-GW-07](gateway.md#NODE-GW-07); a chain known only from the policy table has none ⇒ `UNKNOWN_CHAIN`); a self-call `data` must be canonical before hashing ([NODE-JOB-20](job-api.md#NODE-JOB-20)) | `meta_tx` (all signed) | `MetaTxLib.hashStruct` (`smartcontracts/src/common/MetaTxLib.sol`), `metatx.rs` `digest()`, client libraries |
 | `cosmos` | `sha256(payload)` | payload JSON (`MetaOp`) | contract `metaop` (`metaop/src/lib.rs` = `chains/cosmos/metaop/src/lib.rs`), client libraries |
 | `sui` | `blake2b256([3,0,0] ‖ bcs(vector<u8>(payload)))` | `adapters/sui.rs` `MetaOp::decode` (l.136) | `meta.move` `op_digest`, `adapters/sui.rs` `personal_digest`, client libraries |
 | `aptos` | `sha3_256(payload)` | `adapters/aptos.rs` `MetaOp::decode` (l.149) | `meta.move`, client libraries |
@@ -434,7 +434,7 @@ also checks that the client's own digest functions (`build_terms`/`digest` per f
 `submit_meta_tx` is the struct the submitter would encode after normalization. Required cases (accept unless a code is
 given):
 
-1. EVM open FIXED fee, a payment `MetaTransfer` (`entryRef ≠ 0`) — intent_id equal to the `metatransfer_kat.json` vector in `smartcontracts/evm/test/vectors`.
+1. EVM open FIXED fee, a payment `MetaTransfer` (`entryRef ≠ 0`); case 3a is the `metatransfer_kat.json` vector verbatim.
 2. EVM open mode with garbage in `relayer` and `feeRecipient` ⇒ **same** `intent_id` as case 1;
    `submit_meta_tx.feeRecipient` = `fee_recipient`, `relayer` = 0.
 3. EVM `MODE_RESTRICT_RELAYER` with a lane address (accepted; `may_submit` only for that lane's node).
diff --git a/docs/node/store.md b/docs/node/store.md
index bad2b2d..e4a7ac2 100644
--- a/docs/node/store.md
+++ b/docs/node/store.md
@@ -625,16 +625,16 @@ family = "evm"
 evm_chain_number = 7622
 rpc_urls = ["http://rpc-a:8545", "http://rpc-b:8545"]   # ≥ finality.quorum independent endpoints
 finality = { mode = "depth", depth = 1, quorum = 1 }    # 'depth' | 'tag' | 'instant'
-dex = "0x…"                                     # SCaaSDexV1 (the node reads `settle`), optional
+dex = "0x…"                                     # a SCaaSDex clone (the venue's DEX, the call table's DEX rows), optional
+chain_uid = "0x…"                               # NODE-GW-07; also account_factory, token_factory (call table), optional
 poll_ms = 1000
 stuck_after_secs = 60                           # replace at the same nonce, fee ×1.25
 max_gas_per_tx = 3000000                        # structural breaker
 max_fee_cap_gwei = 500                          # fee ceiling for replacements
 max_inflight = 16                               # per-lane in-flight depth, tunable default (NODE-LANE-24)
 profile = "public"                              # chain_profile; default "private" (NODE-MESH-06)
-fee_recipient = "0x…"                           # optional, EVM/Hedera. Cold wallet: normalization target, published
-                                                # in /v1/mesh/policy, used by fee_recipient_allow = "self_or_zero".
-                                                # Never a lane key. Unset ⇒ normalization writes 0 (fee to the lane).
+fee_recipient = "0x…"                           # optional, EVM/Hedera cold wallet (never a lane key): normalization
+                                                # target, in /v1/mesh/policy; unset ⇒ 0 (fee to the lane).
 tokens = ["0x…"]                                # bootstrap token rows (NODE-MESH-13)
 lanes = [0, 1]                                  # account indexes (submit-lanes.md#lane-keys)
 
diff --git a/docs/node/submit-lanes.md b/docs/node/submit-lanes.md
index 6c403ef..0dab926 100644
--- a/docs/node/submit-lanes.md
+++ b/docs/node/submit-lanes.md
@@ -291,7 +291,8 @@ where they accept fewer. As built the runner does not cap it (PLANNED).
 
 <a id="simulation"></a><a id="NODE-LANE-23"></a>**NODE-LANE-23** — **Simulation before signing is mandatory**, on the
 node's own RPC endpoints (no third-party simulation service). EVM: `eth_estimateGas` from the lane address at
-`pending` (gas limit = estimate + 20 %); non-EVM: `ChainAdapter::build` = build + family simulation (Soroban
+`pending` (gas limit = estimate + 20 %; a contract signer's meta-tx at least 21 000 + 400 k·64/63 + 5 000 for its
+ERC-1271 check; `mtxSettle` raised ×1.5 until an `eth_call` at that gas settles every settlement); non-EVM: `ChainAdapter::build` = build + family simulation (Soroban
 `simulateTransaction`, Sui dry-run/dev-inspect (`sui_dryRun`), Cosmos `tx/simulate`, Aptos simulate, TON emulation, Solana
 `simulateTransaction`; per-family details in [networks/](../networks/README.md)). Simulation narrows but cannot rule out
 a revert: state can change between simulation and inclusion (a race, an allowance spent, a pause switched on, a
@@ -428,10 +429,8 @@ intent. Cost: one `eth_call` per stuck tx per `stuck_after_secs` (60 s) and per
 After `valid_until` the subject nonce of TON/Solana/Aptos/Sui lanes may be pruned (Sui: permissionless `prune`) and read as 0; consumption checks are
 only made while `now ≤ valid_until + clock_skew_secs`, and expiry decides after that.
 
-EVM view names: the target tokens expose the nonce and digest views as `mtxNonce(from, batch)` and `mtxDigest(m)`, and
-the gateway as `mtxExecute` (the alias `executeMetaTransaction` stays, [contracts/metatx.md](../contracts/metatx.md)).
-Transitional (BUILT): deployed tokens and the code paths above use `metaNonce`, `metaTxDigest` and
-`executeMetaTransaction`; the adapter switches by implementation when the renamed tokens are deployed.
+EVM view names (BUILT, P5): `mtxNonce(from, batch)`, `mtxDigest(m)` / `mtxTransferDigest(t)`; the node relays
+`mtxExecute` / `mtxExecuteTransfer` (the alias `executeMetaTransaction` stays, [contracts/metatx.md](../contracts/metatx.md)).
 
 ### 9.1 Shared submit path
 
@@ -562,10 +561,8 @@ batches them.** For gasless unwrap ops ([CTR-MTX-12](../contracts/metatx.md#CTR-
   calldata — single-underlying `unwrap(uint256 amount, address recipient, uint256 minOut)`, multi-underlying
   `unwrap(address underlying, uint256 amount, address recipient, uint256 minOut)`, confidential-token public
   `unwrap(uint256, address)` — with `m.to = m.value = 0` ([NODE-JOB-20](job-api.md#NODE-JOB-20)); the contract checks
-  `recipient ∉ {0, address(this)}`, `0 < out ≤ reserve`, `out ≥ minOut`, burns `⌈out·q⌉`. Transitional (BUILT): the
-  deployed tokens use the `unwrap(address underlying, address recipient, uint256 minOut)` pseudo-op (100 bytes, amount =
-  `m.value`, `m.to == recipient`) with the entry points `mtxUnwrap` and `mtxUnwrapWithFee`, which the allowlist tokens
-  delete.
+  `recipient ∉ {0, address(this)}`, `0 < out ≤ reserve`, `out ≥ minOut`, burns `⌈out·q⌉`; built (P1d, P5: the
+  node relays it as any self-call).
 - The simulation gate runs the full outer transaction (`eth_call`/`eth_estimateGas` at `pending`), so it executes the
   underlying's transfer, `balanceOf` reads and the exact-amount check; it re-simulates immediately before signing the
   outer transaction, as for every job.
diff --git a/smartcontracts/evm/README.md b/smartcontracts/evm/README.md
index 26c7b80..ee0b40b 100644
--- a/smartcontracts/evm/README.md
+++ b/smartcontracts/evm/README.md
@@ -8,9 +8,9 @@ Interface đã chốt cộng các implementation đã có (2026-10-03,
 
 | Contract | File | Ghi chú |
 |---|---|---|
-| `MetaToken` v1 (kind META) | `src/metatx/MetaToken.sol` | clone EIP-1167; tầng 1 standalone / tầng 2 wrapper 1:1; op `pay(bytes32)` và `trade(address,uint256,address)` trong `data` của meta-tx |
+| `NormalToken` / `WrappedToken` (kinds `NORMAL`, `WRAPPED`) | `src/metatx/` | clone EIP-1167 trên `MetaTokenBase` (`MetaTxBase`, `ERC20MetaTx`); `MetaTransaction` + `MetaTransfer` |
 | `OpenFactory` | `src/factory/OpenFactory.sol` | hiện thực `IOpenFactory`; salt theo người tạo |
-| `MetaTxDex` | `src/dex/MetaTxDex.sol` | khớp hai chân meta-tx, không allowance, fill-or-kill |
+| `SCaaSDex` | `src/dex/SCaaSDex.sol` | clone per DEX (`createDex`): `mtxSettle` một taker nhiều maker, outside legs qua `DexPuller` |
 | Allowance chỉ giữa hợp đồng | `src/metatx/ERC20MetaTx.sol` | `approve` từ chối spender không phải hợp đồng, `transferFrom` từ chối caller không phải hợp đồng; EOA uỷ quyền EIP-7702 (`0xef0100‖addr`) = EOA; hợp đồng đang chạy constructor = EOA (R26) |
 | `MandateWallet` | `src/wallet/MandateWallet.sol` | ví một người trả cho auto-pay delegated: mandate on-chain (hạn mức lần/kỳ, payee, hạn), ERC-1271 cho chủ ví, trả bằng `payWithFee`. Deploy ngoài Odoo: `forge create src/wallet/MandateWallet.sol:MandateWallet --constructor-args <owner>` (R29) |
 | Deploy | `script/Deploy.s.sol` | ghi `deployments/<chainid>.json` |
@@ -18,7 +18,7 @@ Interface đã chốt cộng các implementation đã có (2026-10-03,
 Zether is built (P3: the kinds `NORMAL_ZETHER` and `WRAPPED_ZETHER` in `src/zether/` as `NormalZetherToken`, `WrappedZetherToken`, `ZetherLayer`, `ZetherLib`, `ZetherStatements`, `ZetherVerifierBn254`, `ZetherVerifierBls12381`;
 `src/registry/UniversalAccountRegistry.sol`; the old `ZetherToken` line is in `legacy/p3/`, not built), unaudited and gated to dev chains 31337/1337 (`ZetherSafety`,
 RS2-1); see `docs/contracts/zether.md` (CTR-ZTH-02) and `docs/contracts/README.md`. `test/vectors/metatx_kat.json` là vector v3 `MetaTransaction` (MetaTxBase);
-`test/vectors/metatx_v1_kat.json` là struct v1 đã build, dùng chung với Odoo (`dms_blockchain/lib/eip712.py`) và relayer (`scaas-node`) đến P5.
+The v1 line (`MetaToken`, `HederaMetaToken`, `OpenFactoryV1`, `MetaTxDex`, `SCaaSDexV1`, `metatx_v1_kat.json`, `dex_kat.json`) is in `legacy/p5/`, not built (P5).
 
 ## Mô hình: factory mở
 
``````

### Final

- [ ] **Whole branch.** From the worktree root after Task 7: full `forge build` and `forge test` (844), size gate 0 errors,
  `FOUNDRY_PROFILE=private7622 forge build`, `cargo test --lib` (254), `cargo test --test mesh_vectors --test fuzz`,
  clippy, e2e 4/4, e2e_hedera 1/1, clientkeys 60/58/2, `docs_check.py check` 0 errors, `facts check` 0 misses.
- [ ] **Review** against the Review Focus above; then merge to `main` (owner), and hand the bamboo-dms list to its
  owner.
