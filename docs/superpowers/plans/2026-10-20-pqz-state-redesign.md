# PQZ state and credit-cap redesign (plan Task 5h): implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (one implementer and one reviewer per task). Steps use checkbox (`- [ ]`) syntax.

**Status:** plan (designer for plan Task 5h, 2026-10-20), **waiting for the owner's review of the spec** (Task 0). Nothing here is built.

**Base:** `main` at `e85d8b4`; Task 5g-Z (canonical Zether verifiers) merges first, then this plan's branches start from that main.

**Goal.** The owner rulings of 2026-10-19 (decisions CTR-PQZ-06, -07, -08 Change lines; plan
[`2026-10-19-pqzl-fs3.md`](2026-10-19-pqzl-fs3.md) Task 5h):
1. ciphertexts in contract state (not only hashes), so they survive EIP-4444 history expiry;
2. **B**: credits are never refused, the pending queue is unbounded, rollovers go strictly in order and never lose or
   skip an entry, a rollover stops before `acc` exceeds the cap, the owner's refresh resets it;
3. `ROLL_MAX` raised to the largest batch under 2^24 gas with ≈ 25 % margin;
4. **A'**: larger lattice parameters, `K_MAX` ≈ 65,536, a new `proofSystemId` for PQZL and PQZH.
Order: B and the state layout first (today's parameters, no relation change), then A'.

**Spec:** [`docs/superpowers/specs/2026-10-20-pqz-state-redesign.md`](../specs/2026-10-20-pqz-state-redesign.md)
(options with numbers, the recommendation, risks, open questions O1–O9). Normative text after the owner's review:
`docs/contracts/pq-zero-knowledge.md` §4.1, §4.3, §4.4, §7.1, §7.4–§7.8, CTR-PQZ-06, -07, -08, threats T7, T8, T22, T23.

## Global constraints

- Heavy jobs under `scripts/capped` (forge, cargo `-j2`, the Sage image); Docker always with `--memory`; never poll; stop
  every background shell before reporting.
- No merge, no push by implementers; the controller merges after the owner's approval.
- Decisions into `docs/decisions.md` in full (content + status), "controller proposal, owner may override".
- Timing measurements (precompile calibration, verify p99) only with the owner's go-ahead; forge gas tests are fine.
- `scripts/size_gate.py` for every contract whose bytecode changes; every PQZ token implementation stays at least
  **4 KiB under** the 65,536-byte test-chain limit (D14).
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions (controller proposals; the owner may override)

Numbers: the spec, measured by `smartcontracts/evm/test/research/PqzStateGas.t.sol`
(`smartcontracts/evm/runs/2026-10-20-5h-state-gas.txt`) and `pqz-core/pqzl/params/aprime/`.

| # | Decision | Proposal | Why |
|---|---|---|---|
| D1 | Where ciphertexts live | One SSTORE2 **op blob** per debit operation: transfers `salt ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖ UA_j)_{j<M} ‖ v_f` (= today's bundle `R` plus `v_f`), burn / refresh `u' ‖ v_f`. Written once, never deleted. | One shared `u` per operation (CTR-PQZ-04) stored once; 200 gas per byte; reads are ≈ 4 k gas per 16 KB (EXTCODECOPY). Slots cost 11.4 M per ciphertext (rejected), one SSTORE2 per credit repeats `u` M times (rejected). |
| D2 | A pending credit | **One slot** `blob(160) ‖ g(8) ‖ G(8) ‖ j(8) ‖ block(64)` in `pending[ua][i]`; `pendingHash` removed. | The bytes are in the blob; 22.1 k per credit instead of keccak + slot; the block feeds D6. |
| D3 | `acc` | After a debit: a **reference** to the debit's blob (`u_0`, `v_f`), one slot. After a rollover: **materialised** in `CT/32` slots (516; 708 under A'), overwritten in place (5 k per slot), plus `accHash` for D5. The slots are never zeroed. | A debit costs no `acc` write; rollovers overwrite instead of growing state (an SSTORE2 per rollover would leave 16.5 KB of garbage each time). The first materialisation of an account is zero → non-zero (22.1 k per slot): D8. |
| D4 | Debit effects | `acc` = the fresh reference, `accUnits = 1`, **`rolled = floor = p`** (a debit with `p < rolled` un-rolls `[p, rolled)`: those credits are pending again and will be rolled again — nothing lost, nothing skipped); the dead pending slots `[cleared, p)` deleted (≤ 2·`INLINE_MAX`). | Every debit leaves a fresh, unmaterialised `acc`; one rule for both cases. |
| D5 | How a debit gets `acc` and `inline` | The contract reads them from state (`inline` from the blobs). Optional calldata **hint**: the materialised `acc`, used when `keccak == accHash`, else ignored (state read). The `acc` / `inline` arguments of every debit entry point are replaced by `bytes accHint`. | A stale hint never reverts; the hint saves the 516 cold SLOADs (≈ 1.1 M) of a materialised `acc`. |
| D6 | Race-freedom without W-E's base | **Remove** `baseHash` / `baseRolled` / `baseUnits` and the base branch of `_total` (review carry-over). Add **`ROLL_AGE = 24` blocks, enforced**: a rollover may roll entry `i` only if `block.number ≥ block_i + ROLL_AGE`. A debit submitted within `ROLL_AGE` blocks of the state it was proven on never sees `rolled > p`; after that, `p ≥ rolled − INLINE_MAX` is still accepted (D4). | With `acc` in state no calldata can go stale (D5); the only race left is "rolled past `p` by more than `INLINE_MAX`", which needs young credits: today's honest-keeper `KEEPER_AGE` made a contract rule. |
| D7 | B: credits | No `RefreshRequired` on a credit (op 1 and op 7); `pendingCount` uint64, unbounded. | Owner ruling B. |
| D8 | B: rollover | `pqzRollOver(ua, n)`: anyone; strictly `[rolled, rolled + n')` with `n' = min(n, K_MAX − 1 − accUnits)`, reverts `CapReached(ua)` when `n' = 0`, `RollTooYoung` per D6; `n ≤ ROLL_MAX`; `AccNotPrepared` until `pqzPrepareAcc(ua, half)` (permissionless, idempotent, ≈ 5.7 M per half; A' ≈ 7.8 M) wrote a non-zero placeholder into both halves of the account's `acc` words; deletes the pending slots below `rolled − INLINE_MAX`. Measured (spec §5.3), pinned by gas tests: **today's parameters `ROLL_MAX = 256`** (12.11 M, 72.2 % of 2^24); **A' (n = 2816) `ROLL_MAX = 176`** (≈ 12.0 M; O9). | Ordered, never skipping, stops at the cap; ≈ 2.78 M + 36.3 k per entry (A' 3.81 M + 46.6 k) instead of ≈ 0.52 M of calldata per ciphertext; the first materialisation (11.4 M; A' 15.8 M) cannot share a transaction with a batch under A'. |
| D9 | Units | `accUnits` uint32 (`K_MAX = 65,536` does not fit uint16); `unitsOf(T) = accUnits + (p − rolled) + 1 ≤ K_MAX` stays the debit check. | Review carry-over. |
| D10 | Credit fee (decoy flood) | `ConfidentialConfig.multiLegFee` becomes the **per-credit fee** of both transfer paths (op 1 too: `fee = confidentialFee + creditFee`), paid to every credited UA's `plainPending`; on the SCaaS chains (`PqzSafety.requireAllowedChain`) `init` refuses 0. Field name kept, so the Zether kinds do not change. The amount is the deployer's; the floor value is O4. | The sender pays the recipient for the state and rollover work it causes; the same for every leg (reveals nothing). |
| D11 | Storage modes | Kept as entry points (W-A bindings unchanged). BUNDLE: `entryPtr[ref]` = the op blob (no second SSTORE2); HASH: the blob plus the memo (the hash of `R` dropped); NONE: the blob only. Disclosure reads `R` out of the blob. | The blob is `R`; COMPACT / NONE no longer save the 3.4 M (O5). |
| D12 | Events | Pointers instead of bytes: `PqzTransfer(entryRef, fromUA, toUA, salt, blob)`, `PqzTransferMulti(…, blob)`, `PqzBurned(ua, amount, recipient, blob)`, new `PqzDebited(ua, rolled, floor, blob)` (review N4), `PqzRolled(ua, rolled, accUnits, accHash)`. | The bytes are in state; logs cost 8 gas per byte (≈ 134 k per transfer). |
| D13 | Views | `pqzAccount(ua)` (counters, `accUnits`, flags, `plainPending`, `sendCounter`, the `acc` blob), `pqzAcc(ua)` (bytes), `pqzPending(ua, i)` (slot fields) and `pqzPendingCt(ua, i)` (bytes), `pqzEntryBlob(entryRef)`. | Wallets restore from state alone (owner ruling); review N4 / open question 2 of 5g. |
| D14 | Library split (controller 2026-10-20) | `PqzLib` (20,569 B) splits by concern into four DELEGATECALL libraries in the same ERC-7201 namespace: **`PqzStateLib`** (init, shield, credit append, rollover, views), **`PqzTransferLib`** (op 1, op 7), **`PqzBurnLib`** (burn, refresh, unwrap), **`PqzViewLib`** (statement views, disclosure); shared internals (`_header`, `_check`, `_total`, `_debit`) in an internal library compiled into each. Every token implementation keeps ≥ 4 KiB under 65,536 B and every library under 24,576 B. | Room for the 5h logic and per-call code loading only what the call needs (owner: as the Zether verifier split). Projected sizes: spec §8. |
| D15 | Relayed mode binding (review L1, T18) | Fold the transfer mode into every binding: relayed `binding = keccak256(abi.encode(envelopeBinding, uint8(mode)))`; the unwrap leg / `minOut` likewise. | Done with the API change of D5 (one client break, not two). |
| D16 | A' parameters | **n = 2816 (k = 44), q = 2^54 − 327, Δ = 2^32 − 1, β_s = 42, β_e = 189, `K_MAX = 65,536`, `e_T ∈ [−2^30, 2^30)`, `M_i < 2^20`, carries 17 bits** (R_TX 1,199 bits, 19 binary polys). Alternative n = 2688 (k = 42) if O2 prefers size. New ids: PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k44-q54l4/v1")`, PQZH Ligero v2. | Spec §6: encryption β 520 (≥ 450 also with 80 hints: 496.8), mint margin 3.08×, sizes +37.5 %. |
| D17 | Order | B + state (Tasks 1–6) on today's parameters and ids, reviewed and merged; then A' (Tasks 7–9); then plan fs3 Tasks 6 and 13 (package, 7622 reset, gas). | Owner: "B and the state layout first, then A'". B changes no relation; A' changes every relation. |

## Review Focus (inputs most likely to bite)

1. **Un-roll (D4) and deletion (D8) together.** A debit with `p < rolled` needs `pending[p .. rolled)`; rollovers delete only
   below `rolled − INLINE_MAX`, and `p ≥ rolled − INLINE_MAX`. A test must debit at exactly `p = rolled − INLINE_MAX`
   right after a rollover of `ROLL_MAX` entries.
2. **The hint (D5) must never decide `T`.** Only `keccak(hint) == accHash` with the materialised flag set selects it;
   every other case reads state. Test a stale hint (a rollover in between) and a hint on a fresh `acc`.
3. **`ROLL_AGE` vs the owner's own debit.** Debits may include young entries inline; only rollovers are age-gated.
4. **The cap clamp.** `n' = min(n, K_MAX − 1 − accUnits)`; a rollover at the cap reverts `CapReached`; the debit's
   `unitsOf(T)` check stays (defence in depth).
5. **Lane overflow under A'.** 64-bit lanes hold `2^64 / 2^54 = 1024` terms: `ROLL_MAX + 1 + INLINE_MAX` must stay ≤ 1023
   (asserted by a test with every coefficient at `q − 1`).
6. **First materialisation gas.** `pqzPrepareAcc` halves stay under `0.75 · 2^24` (A' too); a rollover before both
   halves reverts; the `ROLL_MAX` gas test runs on a prepared account with every entry from a distinct cold blob, in a
   transaction of its own (forge: fill in `setUp`, as `PqzStateSteadyGasTest*`; a slot rewritten twice in one test
   is "dirty" and understates by 2,800).
7. **Disclosure reads `R` from the blob.** `R` = the blob minus the trailing `v_f`; `ciphertextHash` / the bundle shape
   rules stay byte-identical with today's `R` (vectors `statement_*` unchanged).
8. **Size gate.** D14 before the logic (Task 1), so later tasks see real headroom.

## Tasks

### Task 0: Owner review and rulings
- [ ] The owner reads the spec and rules on O1–O8 (O1: A' still wanted with B; O2: n = 2816 vs 2688; O3: mint margin;
  O4: credit-fee floor; O5: storage modes; O6: ROLL_AGE; O7: refresh cost; O8: MAX_INPUT / verify-time budget;
  O9: A' `ROLL_MAX` 176 and op 7 M = 8 over the cap).
- [ ] Record the rulings and D1–D17 in `docs/decisions.md` (Change lines under CTR-PQZ-06, -07, -08, -03, -09; D14 under
  CTR-PQZ-07 or a new CTR id per the docs rules).
- [ ] Worktree `pqz-state-b` from main after 5g-Z.

### Task 1: Library split, no behaviour change (D14)
**Files:** `smartcontracts/evm/src/pqz/PqzLib.sol` → `PqzStateLib.sol`, `PqzTransferLib.sol`, `PqzBurnLib.sol`,
`PqzViewLib.sol`, `PqzCore.sol` (internal); `PqzLayer.sol`, `NoUnderlyingPqzToken.sol`, `UnderlyingPqzToken.sol`;
`test/pqz/helpers/PqzFixture.sol` and the four suites (linking); `script/pqz/e2e.py` (deploys four libraries);
`size-baseline.json`.
- [ ] Move the public functions per D14; the shared private steps become `internal` in `PqzCore`.
- [ ] Every existing PQZ forge suite green with no test change other than linking; statement views byte-identical
  (`test_transferStatementMatchesVector`).
- [ ] `forge build --sizes` + `scripts/size_gate.py`: tokens ≥ 4 KiB under 65,536 B, libraries < 24,576 B; log
  `smartcontracts/evm/runs/<date>-5h-split-sizes.txt`. Commit.

### Task 2: State layout and B (D1–D9)
**Files:** `PqzStateLib.sol`, `PqzTransferLib.sol`, `PqzBurnLib.sol`, `PqzCore.sol`, `PqzCt.sol` (`loadBlob`, lane add
from memory), `IPqzToken.sol` (errors `CapReached`, `RollTooYoung`, `AccNotPrepared`; `RefreshRequired` and `AccMismatch` removed),
`PqzLayer.sol` (entry points without `acc` / `inline`, `pqzRollOver(ua, n)`, `pqzPrepareAcc(ua, half)`).
- [ ] `Account`: scalars in ≤ 3 slots (`pendingCount`, `rolled`, `floor`, `cleared`; the `acc` reference, `accUnits`
  uint32, flags; `sendCounter`, `plainPending`), `accHash`, `pending` mapping, `uint256[CT/32]` acc words.
- [ ] Debit: `_total` from state (D5), effects D4; credits D2 / D7; op blob D1 (single, multi, burn / refresh).
- [ ] Rollover D8 with `ROLL_AGE` (D6); deletion below `rolled − INLINE_MAX`; `pqzPrepareAcc`.
- [ ] Tests (new file `test/pqz/PqzState.t.sol` + updates): credits beyond the old 1,024 accepted; ordered rollover,
  clamp at the cap, `CapReached`, refresh resets; un-roll at `p = rolled − INLINE_MAX` (Review Focus 1); stale and fresh
  hints (2); `RollTooYoung` and a debit with young inline credits (3); the two W-E race tests rewritten as "a rollover
  between prove and submit still settles" (kept as regressions); restore-from-state: rebuild `acc` and the pending
  ciphertexts from the views only and compare with the bytes the test wrote; a forge invariant "every entry `< p` of a
  debit is in exactly one of: the spent `T`, `acc`, pending".
- [ ] Gas tests pinning `ROLL_MAX` and the `pqzPrepareAcc` halves (each under `0.75 · 2^24` with distinct cold blobs; Review
  Focus 6) and the per-op gas table of spec §5.4; log `runs/<date>-5h-b-gas.txt`. Commit.

### Task 3: Entry semantics, fee, events, views, bindings (D10–D13, D15)
- [ ] D11 storage modes on the blob; disclosure from the blob; `ciphertextHash` unchanged in value.
- [ ] D10 credit fee on op 1 and op 7; the SCaaS-chain floor in `init`; Zether kinds untouched (still refuse non-zero).
- [ ] D12 events, D13 views; D15 relayed mode binding and unwrap parameters (statement views, `e2e.py`).
- [ ] Tests: fee per credit on both paths; `init` refuses 0 on 7622 / 22776 ids; each event; each view; relayed
  `…NoBundle` replay of a BUNDLE envelope fails (L1). Commit.

### Task 4: Clients, tools, vectors
- [ ] `smartcontracts/evm/script/pqz/e2e.py` and `pqz-core/nethermind/chain/e2e.py`: no `acc` / `inline` in calldata,
  rollover by count, wallet restore from the views; the P6h wallet TODO gets the view list.
- [ ] Statement vectors unchanged (no relation change); the relayed-binding statements of D15 regenerated where a
  vector holds one; list every changed artefact. Commit.

### Task 5: Spec and decisions
- [ ] `docs/contracts/pq-zero-knowledge.md`: §7.1 state table and flow, §7.4 / §7.4.1 checks and effects, §7.5, §7.6
  rollover, §7.8 events, CTR-PQZ-06 (B), -07 (state), -08 (no base; `ROLL_AGE`), threats T7, T8, T22, T23 rewritten with
  the measured numbers; CTR-PQZ-23 / -25 for D11.
- [ ] `docs/decisions.md` statuses; `python3 -I scripts/docs_check.py check` 0 errors. Commit.

### Task 6: Review and merge of B + state
- [ ] Reviewer (Claude sub-agent; Codex only on the owner's request): spec conformance, the Review Focus items, gas
  logs, sizes. Fixes, then the controller merges after the owner's approval.

### Task 7: A' parameters and estimates (D16)
**Files:** `pqz-core/pqzl/params/` (new `*_params.sage` for every relation: reg, tx, tx0, burn, ds, dr, txm2 / 4 / 8
with and without the auditor), headers by `regen.sh`, `to_rust.py` output, `estimator-*.txt`, `anon/hints-anon.txt`
rerun at the new `n, q, β`.
- [ ] Leaky-LWE-Estimator at 144 worst-case hints for one randomness group of 8 legs + auditor (spec §6.2: ≈ 478
  extrapolated); if ≥ 450, op 7 M = 8 uses G = 1 under A' (new relation spec), else M ≤ 4 on chain (O9).
- [ ] `run_e_s1.sh` on every new spec; additionally require the proof MLWE's **dual_hybrid** β ≥ 450 (at q ≈ 2^54 the
  codegen's rank 41 reaches usvp 465 but dual_hybrid 447 / 448: raise `kmlwe_min` until both pass).
- [ ] Full `aprime.sage` part 3 for the chosen candidate (both models), the leaky-LWE-Estimator hint table at 16–144
  hints, `e_s0.py` adapted (exactness, Fiat–Shamir rounds with the new q).
- [ ] Owner checkpoint on the measured proof sizes vs `MAX_PROOF` (98,304) and `MAX_INPUT` (393,216) before Task 8.

### Task 8: A' in the cores, PQZH, codec, contracts
- [ ] C and Rust PQZL: `N`, `k`, `q`, `Δ`, norm bounds, bit layouts (M 20, carries 17, `e_T` 31 bits), `K_MAX`, NTT
  constants for the new q (q ≡ 9 mod 16 keeps `l = 4`), the keys / Enc / Dec KATs; the arena sizes re-measured.
- [ ] PQZH Ligero: the field changes to the new q (54-bit products still fit u128; the wasm32 21-bit split becomes three
  18-bit limbs), constraint systems for the new widths; its id bumps.
- [ ] `pqz-stmt`: lengths per form, `MAX_PROOF(id)`, `MAX_INPUT` (op 7 M = 8 with the auditor no longer fits 384 KiB, spec
  §6.4), the new ids; the Nethermind plugin limits.
- [ ] Solidity: `PqzCt` (`Q`, `DELTA`, `PK`, `CT`, `ZERO_HASH`), `ROLL_MAX` re-pinned (176 measured on the prototype), `PqzSafety`
  ids, probe proofs and the self-test hash.
- [ ] Vectors, `pqz_kat.py`, fuzz seeds regenerated; native = wasm32; C = Rust; `gate.sh fin`.

### Task 9: A' review, gas re-calibration, roll-out
- [ ] Independent review of the parameter change (the noise budget derivation of spec §6.2, the estimator logs).
- [ ] Precompile gas calibration with the owner's go-ahead (timing), the 60 ms p99 verify limit checked for every form
  (risk: R_TXM M = 8 was 51.0 ms p99 in wasm32 at today's size).
- [ ] Then plan fs3 Task 6 (package) and Task 13 (7622 reset, gas), which wait for 5h.

## Out of scope
Mainnet 22776. Classical Zether contracts (unchanged; Task 5g-Z is separate). Node-level rate limits for credit-creating
transactions (an operations item, named in the spec). Keeper software (P6i).

## Critical files
- `smartcontracts/evm/src/pqz/PqzLib.sol` (`_receiver` 231, `_legs` 401, `_credit` 302, `_creditLegs` 455, `rollOver` 580,
  `_total` 769, `_debit` 828), `PqzCt.sol`, `PqzLayer.sol` (entry points 128–188), `IPqzToken.sol`
- `smartcontracts/evm/test/pqz/PqzNone.t.sol` (race tests 501–583), `PqzMulti.t.sol`, `helpers/PqzFixture.sol`
- `smartcontracts/evm/test/research/PqzStateGas.t.sol` (the measurement prototype)
- `pqz-core/pqzl/params/aprime/` (A' budget, estimates, sizing specs), `pqz-core/stmt/src/lib.rs` (98–101 limits)
- `docs/contracts/pq-zero-knowledge.md` §4.1–§4.4, §7.1–§7.8
