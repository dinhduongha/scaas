# Spec review 2: Round 4 relayer mesh, rev 2 (1408 lines)

**Verdict: FIX-THEN-GO**

All 25 findings from review 1 were addressed in the text. I checked each fix against the spec and the code at `main`
3a789d2, not only the §16 table. Every safety fix holds: the Critical, all six Highs, and M1–M10 as designed.

The revision brings in one new High, and it is a liveness gap rather than a leak or a loss of money. R86's
registered-token gate keys on `contract`. For four of the six R77 families, `contract` is the payer's own account, never
a token. The other open items are lifecycle details of the new in-flight set, a re-ingest loop caused by deleting failed
rows, and a server-only-field fix that would not pass its own test. None of them needs a ruling.

Read-only review; no builds.

---

## Review-1 findings: verification

| # | Status | Evidence in rev 2 |
|---|---|---|
| C1 | **fixed** | R84 and the §8.4 `normalize()` cover the gateway (S0, before simulation) and mesh work. Vector 2 now asserts `submit_meta_tx`; E1 asserts the fee lands in B's wallet. The claim that Odoo builds `fee=0, feeRecipient=0` holds (`blockchain_payment_request.py:141,218-219`). See N8 for the Hedera path. |
| H1 | **fixed** | The rejection cache is gone; DUPLICATE now only matches stored rows, and only rows that passed L2 are stored. Non-EVM routing fields are decoded from the payload, and the decoders exist: `sui.rs:136`, `aptos.rs:149`, `solana.rs:154`, `ton.rs:292/486`. Cosmos has none (N9). `body_hash` is in `hub_msg`; vectors 26–27. Deleting failed rows creates N3. |
| H2 | **fixed** | L2 rejects only `published_at > now + skew`; vector 28; E10. |
| H3 | **fixed** | Covers the reverted receipt (`track()`) and `follow()` `TxStatus::Reverted`. `consumed` keeps business state pending, and `FAILED_STATES` is unchanged, so `_fail_dependents` does not fire. E12; S1a tests. See N5 for the transition added on `mined`. |
| H4 | **fixed for EVM, Hedera and Cosmos** | Effective fee per `FeePolicy.compute`; `CHECK(NOT submit OR contract_address <> '*')`. The registered-token gate does not fit the account-model families (N1). |
| H5 | **fixed** | R85; `may_export` has `row.source != 'peer'` on the private branch; E5 includes B re-serving to C. |
| H6 | **fixed in principle** | Per-chain in-flight set, and a duplicate on publish flips the row's owner. Membership and lifecycle are incomplete (N2). |
| M1 | **fixed** | `default-features = false` with `ring`, and `builder_with_provider`. The PKCS#8 prefix parse is right: `302e020100300506032b657004220420` followed by the seed. S5 gate checks that the lock gains no `aws-lc-rs`. |
| M2 | **fixed** | Store rows go through `plan()`; `nonce_at` is declared as new. Only non-terminal rows should be fed in (N6). |
| M3 | **mostly fixed** | Transition table, fail-closed reads, janitor rescue of stuck `submitting` rows, late-report no-op. One edge is missing (N7). |
| M4 | **fixed** | Per-request `PEER_SUSPENDED`, handshake timeout, connection semaphore, connection age; E6. |
| M5 | **fixed** | `store_id` in `meta`, pages, policy and `peer_cursor`; E11. |
| M6 | **fixed** | `op_consumed(&Job)` returns `None` except for `pay`; non-EVM bus limited to `pay`. |
| M7 | **fixed** | The decoded relayer is compared with `lanes()[i].address`. For TON, `ton.rs:952` confirms that address is the W5 lane wallet, which is what the contract compares. |
| M8 | **fixed** | §3.3 table. |
| M9 | **fixed** | L3 tests the label or the chain profile; vector 25. |
| M10 | **mostly fixed** | E1 is rewritten correctly, and E10–E12 are added. E4 still cannot produce a stuck tx (N11). |
| L1–L8 | **fixed** | `is_dev_chain` exists (`blockchain_chain.py:77`). Manifest is `19.0.1.0.0`, so the `19.0.1.1.0` migration path is valid. L4's mechanism does not work as written (N4). |
| O1–O4 | **applied** | Full pages only; no `seen_rejected`; no `mesh_report`; S1a/S1b split. Stream order S0 → S1a → S2 → S3 → S1b → … is consistent: S1b's vector test needs S3's file, and S3 comes first. |

---

## Open findings

### High

**N1. R86's registered-token gate can never pass for Sui, Aptos, TON and Solana (§7.2 L3, §10.2, R86, R77)**

For these families the op `contract` is the payer's own on-chain account, not the token:
- Sui: `contract = derive_account(token.address, payer)` (`dms_blockchain/lib/fam_sui.py:159,167`).
- Aptos: `contract = account` (`fam_aptos.py:233`).
- Solana: `contract = account_of(program, payer)` (`fam_solana.py:176,185`).
- TON: `contract = jetton_wallet_address(payer, master, code)` (`fam_ton.py:296-312`).

So `contract ∈ node_config.tokens` is never true. Odoo also rejects every way to configure submission for them: the
`@api.constrains` requires the contract to be an active token, and the CHECK forbids `*` with `submit`. A policy row
cannot list per-payer accounts either.

Result: the bus can hold and forward these four families but **never submits** them, which contradicts R77. It fails
silently and closed (liveness only). No test catches it: there is no non-EVM e2e, and the vectors carry
`"registered": true` as an input.

Fix: define `token_of(decoded)` per family and gate on that, keeping `contract` for routing.

| Family | `token_of` |
|---|---|
| EVM, Hedera, Cosmos | `contract` |
| Solana | `asset` from the payload |
| Sui | `extra.registry` (bound by `body_hash`), with `derive_account(registry, from) == contract` checked |
| Aptos | the token, with `account_of(…) == contract` checked (`aptos.rs:207`) |
| TON | the jetton master, with `jetton_wallet_address(from, master, code) == contract` checked (`ton.rs:526`, code hash from the token record) |

The policy `contract` column holds `token_of` for these families. Add vectors 10–13 with `may_submit = true` computed,
not given.

### Medium

**N2. The in-flight digest set has no complete lifecycle and misses the non-EVM lanes (§8.3, §8.4, §8.6, G2)**

- (a) Release is only "terminal outcome of the outer tx or gap-filled". The Odoo path inserts *before signing*, then can
  exit without any outer tx: a transient simulate or fee error (`requeue`), a simulate revert (`dead` or `consumed`), a
  journal-write retry, an open breaker. If the digest is not released on those exits, every later claim of that job
  finds it "in flight". The job keeps bouncing back to `queued` until it expires and goes `dead`, a failed payment.
  Specify a guard that is released on every exit that does not leave a `Sent` behind.
- (b) Members are listed as "every Submitter lane, the gateway, the mesh scheduler". The non-EVM `lane_runner` /
  `step_once` (`adapter.rs:161,335`) runs Odoo jobs and will also run mesh work. Without it in the set, non-EVM G2 is
  still false: lane A can sign an Odoo job while lane B signs the same digest from the mesh.
- (c) When the Odoo path finds the digest present, it claims, reports `queued`, and claims again on the next poll.
  `attempt_count` grows and Odoo takes several writes per second for the whole time the mesh tx is in flight. Instead,
  check `job.digest` from the `relay_poll` payload (it is there: `_payload`, `blockchain_relay_job.py:146,157`) and skip
  the job *before* `relay_claim`.

**N3. Deleting failed rows without a tombstone causes a re-ingest and re-simulate loop (§6, T6)**

With no rejection cache and failed rows deleted, the same failed envelope comes back on every poll while it sits in the
peer's last `cursor_overlap` (200) rows. Each time, our node runs `metaTxDigest` and simulates it again.

A malicious peer can make us burn up to about 2 × `peer_intents_per_sec` eth_calls per second at no cost to itself.
Honest-but-failing intents (payer balance short) are also re-simulated about once a second from every peer that holds
them, for up to `valid_until`.

Fix: keep a tombstone keyed by `(intent_id, body_hash)` until `valid_until`. The same body is skipped; a different
body (the honest copy) is still evaluated. That keeps H1's protection.

**N4. Stripping server-only fields from `vals` does not stop `default_*` context keys (§10.3, test in §13.4)**

`create()` strips `landed_elsewhere` / `mesh_published_datetime` from `vals`, then `super().create()` fills the missing
fields from `default_landed_elsewhere` / `default_mesh_published_datetime` in the context. This happens under `sudo()`
too, and the portal flows create jobs under sudo, so the `env.su` exemption does not help. The §13.4 test "cannot be
set by a `default_` context key" would fail.

Fix: `create` always forces both fields to `False` (an explicit value beats a context default); `write` strips them
unless `env.su`. A pre-set `mesh_published_datetime` silently blocks publication of an open company's job.

### Low

- **N5.** `TRANSITIONS['mined'] = {'reverted', 'consumed'}` (§10.3) is not needed: no path reports `consumed` after a
  successful receipt (the reverted-receipt race happens in `broadcast`). It is also risky. A job our own tx executed
  could be moved to `consumed`, and if the indexer's `final` lags more than an hour, `_cron_expire` would mark an
  executed payment `dead/failed`. Remove it; the late-report no-op already covers ordering noise. Drop "from `mined`"
  from the S1a test as well.
- **N6.** §8.6: feed only non-terminal rows (`submitting` / `broadcast`) into `plan()`. Terminal rows add their
  `outer_nonce` only to `journal_max`. A `consumed` row whose gap-filler was unmined at the crash must not go back to
  `submittable`.
- **N7.** §6 transition table: `broadcast` + reverted receipt **without** consumption has no row (it goes to `failed`,
  and then the N3 tombstone applies). Add it.
- **N8.** R84 is placed in `submit.rs`, but Hedera mesh work runs through the adapter (`lane_runner` →
  `adapters/hedera.rs` `build` from a synthesized `Job`). Normalize once, where the `Job`/`Work` is built from the
  envelope, so every family path gets it.
- **N9.** §4.4 says "no new decoder", but `adapters/cosmos.rs` has no `MetaOp` payload decoder: the payload is JSON that
  the contract parses. A small serde struct is new code. Add it to the T9 fuzz list.
- **N10.** `body_hash` assumes serde_json is built without `preserve_order`. Nothing locked enables it today (only
  `schemars`' optional feature does), but feature unification could switch it on silently. Add a vector whose body keys
  are deliberately unsorted on the wire, so the vector test fails loudly if that happens.
- **N11.** E4 still cannot produce a stuck B: with automine off, `evm_mine` includes every pending tx, so B's tx mines
  and reverts, which is E12's scenario. Make B's `maxFeePerGas` lower than the next base fee
  (`anvil_setNextBlockBaseFeePerGas`), keeping cap headroom so the gap-filler bump is possible.
- **N12.** `GET /v1/intents/{intent_id}` (gateway, R54 auth) returns state and `tx_hash` for any row, including
  private-chain intents ingested from peers. Limit it to `source = 'gateway'` rows.

---

## No new problems found in

- R85 combined with the H6 flip.
- `store_id` reset semantics.
- R84 digest invariance.
- The effective-fee formula against `FeePolicy.sol`.
- The `body_hash` canonical form against Python `json.dumps(sort_keys=True, separators=(',', ':'))`: identical for
  printable ASCII, and both escape `"` and `\`.
- Per-request suspension.
- Post-migration versioning.
- Stream order.
