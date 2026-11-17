# ua-mtx-merge T36: the regulated invariants I1-I13 and the mutant harness

Plan `docs/superpowers/plans/2026-11-04-ua-mtx-merge.md` task T36; spec `docs/superpowers/specs/2026-11-05-regulated-kinds.md`
§8 (invariants) and §9 (mutants). Results: [`mutants.txt`](mutants.txt) (the T36 table), `rerun-t<NN>.txt` (the earlier
harnesses re-run at the T36 tree), [`summary.txt`](summary.txt) (gates). Full forge, cargo and node output stays in
git-ignored `.log` files beside these. Forge gas is deterministic: nothing here is a timing calibration.

## The suite

`test/as/invariant/RegulatedHandler.t.sol` holds `RegCore` (the ghosts and the per-call checks) and three handlers, one per
family, Zether and PQZ apart: `RegPublicHandler` (kinds 8, 9 on `RegFixture`), `RegZetherHandler10/11` (on
`ZetherRegFixture`, the real Zether stack and test prover) and `RegPqzHandler12/13` (on `PqzRegFixture`, the PQZ precompile
mocked). `test/as/invariant/RegulatedInvariants.t.sol` holds one suite per kind (`RegInv8Test` … `RegInv13Test`).

Every call to the token is a low-level call bracketed by `_pre` (a snapshot: each tracked id's public balance and `F`, `P`,
`controls`, `features`, supply, the leg, the minter, the shielded totals) and `_post` (the checks below), made from a fresh
frame (`exec`) so the handler's own memory does not enter the gas of a refusal. A refusal is data, not a handler revert; a
broken invariant counts in `vio[k]` with its first reason in `why`; `hits[k]` counts the checks that had something to check.

| Handler call | What it drives |
|---|---|
| `freeze` (issuer-only or record-backed), `unfreeze`, `recordOrder` (a pool or the token as subject or beneficiary now and then), `revokeOrder`, `forceTransfer` (half the time after the record-backed freeze), `pause`, `unpause`, `operatorTransfer` (bit 22, an operator EOA) | the direct entries of spec §3.1 (bit 21 has no body) |
| `relax`: `revokeRole`, `renounceRole`, `disableFeature`, `cancelGrant`, `grantRole(22)` on bits 5, 6, 7, 10, 22, by the right caller or any other; every other call confirmed after a warp (early, in `[eta, eta + gd]`, after it) by the proposer or another id; `handover` (`transferOwnership`, `acceptOwnership`) | spec §3.6 |
| `attest` (KYC, KYC and `SANCTIONED`, none, `ELIGIBLE_CONTRACT` by the admin, a lapsing one), `warp` | the registry, time |
| 8, 9: `transfer` / `transferToUA`, the typed `mtxExecuteTransfer` relayed with a fee, `payWithFee`, mint or wrap, burn or unwrap, the pause-open set through `mtxExecute` at fee `NONE` and fee-bearing | `_update`, `_uaMove`, the pre row, the fee legs, §3.2 |
| 10, 11: shield, wrap-shield, the single and multi transfer (BUNDLE, COMPACT, a decoy leg with `decoyFee`), unshield, unshield-unwrap, roll-over, public moves | spec §4.1 |
| 12, 13: shield, wrap-shield, the four transfer entries (`shieldIn`, a beneficiary, two decoy legs), unshield, refresh, unshield-unwrap, prepare and roll-over, public moves | spec §4.2 |

| # | Checked | Where |
|---|---|---|
| I1 | `Σ balances == totalSupply` over every tracked id and both pools; Σ UA balances `== balanceOf(UA_POOL)`; wrapped `collateralValue() ≥ totalSupply()`; 10-13 `balanceOf(SHIELD_POOL) == totalShielded × scale` | after every call |
| I2 | each `ForcedTransfer`: the record the call named, live and `RECORD` active before it, subject frozen before it, `to` its beneficiary, amount ≠ 0, Σ ≤ `maxAmount`, `executed` = Σ | the call's events |
| I3 | a frozen id's public balance drops only by its `ForcedTransfer`; roll-over, prepare and the refresh never refused by `F` | after every call |
| I4 | while `P`, a successful call moves no balance or shielded total unless it is a pause-open row or `forceTransfer`; an open row never refused `TokenPaused`; `Paused` ≤ 7 d ahead and ≥ 7 d after the last pause's actual end | every call, `Paused` / `Unpaused` |
| I5 | every id whose public balance rose passes `canReceive`, but a decoy leg's `decoyFee` | after every success |
| I6 | `controls` only loses bits; the controls, `forceTransfer`, `operatorTransfer` and the governance calls leave the leg (`num`, `den`, reserve, `wrapEnabled`) and the minter unchanged | after every call |
| I7 | `until` never drops but by `unfreeze`, `revokeOrder` or T1 replacing a freeze that no longer counts; an issuer-only episode ≤ 60 d; episodes on one id ≥ 30 d apart | every id, after every call |
| I8 | 10-13: `forceTransfer` and `operatorTransfer` read and write no storage slot the shielded views (`accountState`; `pqzAccount`, the last pending entry; `totalShielded`) read | state diff of the call |
| I9 | 10-13: a shield to a frozen or denied `toUA`, a transfer whose recipient or legs are frozen or denied, succeeds when neither `P`, the sender's or `shieldIn` payer's `F`, nor the beneficiary's `F` / `R` refuses it | the call |
| I10 | a refusal by `F`, `P`, `R` or a fee leg: the pre row ≤ 200 k (relayed 8, 9) or, on a confidential site, ≤ 4 × `REGISTRY_GAS` + 200 k (direct, no authorization), before any proof; a receiver or fee-leg refusal after an ECDSA authorization ≤ + 4 × `REGISTRY_GAS` + 50 k | the refused call |
| I11 | not a handler property: `SelectorAudit.t.sol` and the node's `regulated_kinds_rows_equal_contract_*` (T32, T35), both re-run below | — |
| I12 | `controls == (features >> 5) & 0x3F` after every call; a `RelaxProposed` changes neither | after every call |
| I13 | every `RoleRevoked` / `FeatureDisabled` of bits 5-7 and every `RoleGranted` matches a pending of its own action, confirmed by its proposer, in `[eta, eta + gd]`, in the owner generation it was proposed in | the call's events |

`test_everyCheckReached` (each suite) drives one scripted sequence through every check the family has and asserts
`hits[k] > 0` and no violation: a check that never runs cannot pass vacuously. `afterInvariant` logs `hits` and the
refusals of the last run (`-vv`). Two Foundry facts the handler works around: `vm.recordLogs` also records the events of a
reverted call (only a success's events count), and the caller's memory enters a `CALL`'s argument copy (hence `exec`).

Run sizes: 8, 9 64 runs × 128 calls; 10, 11 16 × 48 (real proofs, as `ZetherInvariant.t.sol`); 12, 13 32 × 64. The PQZ
suites at the four sets: `scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test --match-contract 'RegInv1[23]Test'`.

## How to run (from `smartcontracts/evm`, foreground, one at a time)

```text
forge test --match-path 'test/as/invariant/*' -vv                      # the six suites and the non-vacuity tests
runs/2026-11-04-ua-mtx-merge-regulated/run_mutants.sh                  # the T36 mutants -> mutants.txt
RERUN=1 SKIP_T36=1 runs/2026-11-04-ua-mtx-merge-regulated/run_mutants.sh   # the T24-T35 harnesses -> rerun-t<NN>.txt
```

| File | What |
|---|---|
| `mutants.py` | the `t36-*` mutants (spec §9 rows not killed in T24-T35; one per invariant I2, I4, I7, I12) and the `port-*` mutants (an earlier task's mutant whose anchor a later task moved, with today's anchor) |
| `run_mutants.sh` | each mutant against `test/{as/**,governance/{GovRelax,PlusZero,GovDeploy},v2/LinkClosure}` (the invariant suite inside `test/as`), the table `mutant \| test that went red \| red in \| rc` (`red in`: the earlier suites, the T36 invariant suite, or both); `RERUN=1` the earlier harnesses `../2026-11-04-ua-mtx-merge/run_t<NN>_mutants.sh` as they are |
| `mutants.txt`, `rerun-t<NN>.txt`, `summary.txt` | the tables and the gate summary (no absolute paths) |
