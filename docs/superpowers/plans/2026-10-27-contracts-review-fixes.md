# Contracts review part 2 — fix round Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the confirmed findings of the contracts review of 2026-10-26 (1 P0, 2 P1, 5 P2, the P3 list) as the owner ruled on 2026-10-27.

**Architecture:** One branch `review2-fix` from `main` `116d15ce`. Contract-only fixes first (they protect the testnet build at once), then the one classical-Zether protocol bump (label `…/v2` → `…/v3`: independent auditor randomness per leg, strong Fiat–Shamir in the disclosure, `validUntilBlock` on the direct path), then the Zether storage rule, then the P3 hardening, docs last. PQZ proofs, ids and `pqz-core` do not change.

**Tech Stack:** Solidity 0.8 / Foundry 1.8.5 (Amsterdam profile), Rust (`clients/zether-prover`), Python stdlib (vector scripts), `scaas-node` (Rust) for the node items.

**Spec:** `pqz-core/research/code-review-2026-10-26/README.md` — the "Results" rows (file:line, evidence, fix) and "Triage", including the block **Owner rulings 2026-10-27**. Every task below names its finding ids; the row is that task's requirement. Specs to keep in step: `docs/contracts/zether.md`, `docs/contracts/pq-zero-knowledge.md`, `docs/contracts/accounts.md`, `docs/contracts/metatx.md`, `docs/contracts/dex.md`, `docs/decisions.md`.

## Global Constraints

- Owner rulings 2026-10-27: C0-1 → (ii) independent auditor randomness per leg (`C_aud_j = [v_j]G + [t_j]Y_a`, `D_aud_j = [t_j]G`); C0-2 → PQZH value tokens only at `n2048-kmax1024` and only with single-key `mldsa44` / `mldsa65` / `fndsa512` holders; C0-3 → Zether HASH stores `R` by SSTORE2, NONE retired; C0-6 → accept, spec corrected, wallets re-prove on `PendingRange`; items 5–10 of the triage → the controller proposals; `ROLL_MAX` on both relay paths; PQZH option (A).
- Ciphertexts stay in contract state, never only a hash plus calldata / events.
- Every state-changing `mtx*` is relayable; the one recorded exception is native-coin `mtxWrapShield` (C0-18).
- Never assume gas price 0 or a chain's own block limit; one rule for every chain kind; fee = 0 is valid.
- Parameter sets named only `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`.
- Decisions recorded in full in `docs/decisions.md` ("owner ruling 2026-10-27" or "controller proposal, owner may override").
- Heavy commands only through `scripts/capped` (never inside `timeout`); `at-set.sh` one run per worktree at a time.
- No code-size work (owner: not before Glamsterdam); the size gate stays at 0 errors, ratchet entries with a comment.
- Commit per task on `review2-fix`; no merge, no push (controller merges after review).

## Review Focus

1. A Zether audited multi transfer whose two decoy legs carry equal `C_aud` must be impossible to build and refused if submitted — `test_multiAudited_decoysDistinct` (Task 3).
2. A disclosure opening for amount `a ≠ v` must fail even when `s` was chosen after `e` was known — `test_disclosure_lateS_noFalseOpening` (Task 4).
3. A credit or shield to a PQ `msig` holder of a PQZH token at `n2048-kmax1024` must revert, not succeed and lock — `test_pqzhValue_msigHolderRefused` (Task 1).
4. An old `…/v2` Zether proof or statement must be refused by the `…/v3` verifier, and the prover must not build `…/v2` — `test_v2ProofRefused` (Task 3).
5. After NONE is retired, an old `mtxConfidentialTransferNoBundle` call must revert with a clear error, and disclosure of a HASH entry must read `R` from state with no `bundles` argument — `test_noBundleRetired`, `test_disclosure_readsRecordFromState` (Task 5).

---

### Task 1: PQZ token guards (C2-1, C2-3, C0-2 ruling, C2-4, C2-5, C2-6, C2-7, C0-7)

**Files:**
- Modify: `smartcontracts/evm/src/pqz/PqzStateLib.sol` (`init`), `smartcontracts/evm/src/pqz/PqzCore.sol` (credit / shield entry checks, `_common`, `_keyPtr` callers), `smartcontracts/evm/src/pqz/IPqzToken.sol` (errors, views), `smartcontracts/evm/src/pqz/PqzLayer.sol`
- Modify: `pqz-core/params/sets/gen_set.py` + `pqz-core/params/sets/*/set.toml` (new key `pqzh_value = true|false`) → generated `PqzSet.sol` constant `PQZH_VALUE` (true only at `n2048-kmax1024`)
- Test: `smartcontracts/evm/test/pqz/PqzInit.t.sol` (or the existing init test file), `smartcontracts/evm/test/pqz/PqzState.t.sol`

**Interfaces:**
- Produces: `bool internal constant PQZH_VALUE` in `PqzSet`; errors `IPqzToken.PqzhValueUnsupported()`, `IPqzToken.PqzhHolderKind(bytes32 ua, uint16 kind)`.

- [ ] **Step 1: Failing tests.** `test_init_pqzhRefusedWithoutValueSets` (at a set with `PQZH_VALUE == false`, `init` with the PQZH verifier reverts `PqzhValueUnsupported`); `test_init_zeroAuditorRefused` (FULL and OPTIONAL with 32 zero bytes revert `AccountNotRegistered(0)`); `test_pqzhValue_msigHolderRefused` (n2048 PQZH token: `mtxShield` and a credit leg to a 2-of-2 `mldsa65` msig holder revert `PqzhHolderKind(ua, kind)` with the registry's `msig` kind id); `test_pqzhValue_singleKeyHolders` (mldsa44 / mldsa65 / fndsa512 holders accepted). Plus one test per P3 row C2-4 … C2-7 and C0-7 as the README row's fix states.
- [ ] **Step 2:** Run `scripts/capped smartcontracts/evm/script/pqz/at-set.sh n2304-kmax4096 test --match-path 'test/pqz/*'` — the new tests FAIL.
- [ ] **Step 3:** Implement: `init` reverts `PqzhValueUnsupported` when `s.psid == PqzSet.PQZH_ID && !PqzSet.PQZH_VALUE` (registration and disclosure through `UAPqzVerifier` unchanged); the zero-auditor line of row C2-3; on a PQZH token every entry that creates a holder's pending entry (shield, credit legs, op 7 legs, fee beneficiary) checks the holder's UA kind ∈ {`mldsa44`, `mldsa65`, `fndsa512`} via the registry record; C0-7 option (1): the fee beneficiary is any registered UA-ledger receiver (no PQZ key needed); C2-4 … C2-7 as their rows.
- [ ] **Step 4:** `gen_set.py --all --check` clean; the PQZ suites pass at all four sets (`at-set.sh <set> test --match-path 'test/pqz/*'`).
- [ ] **Step 5:** Commit `review2 T1: PQZ token guards (C2-1, C2-3, C0-2, …)`.

### Task 2: UA registry — PQZ holder authorization bound (C0-5, C4-2, C0-11)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistry.sol` (`_pqzAttr`, `_pqEligible`, `_checkMembers`), `smartcontracts/evm/src/ua/IUARegistry.sol` (error `UAPqzHolder(bytes32 ua)` if not present)
- Test: `smartcontracts/evm/test/ua/` (the registry test file that covers `_pqzAttr`), `smartcontracts/evm/test/pqz/PqzStateGas.t.sol` (msig-holder rows)

**Interfaces:**
- Consumes: `PqzSet` gas constants (new `set.toml` key `debit_min_gas` → `gen_set.py` → `PqzSet.PQZ_DEBIT_MIN_GAS`: the cheapest built PQZL debit form's regular gas on the costlier relay path, read from `smartcontracts/evm/runs/2026-10-26-t8d2b-fix-gas-<set>.txt`).
- Produces: `UAPqzHolder(bytes32 ua)` revert in `register` when the holder's worst-case authorization + `PQZ_DEBIT_MIN_GAS` + envelope > 2^24.

- [ ] **Step 1: Failing tests.** `test_register_msigHolderOverBound` (`{fndsa512 ×4, slhdsa128s}, t = 5` with a PQZ key reverts `UAPqzHolder`); `test_register_msigHolderWithinBound` (2-of-2 `mldsa65` accepted at PQZL); C4-2's at-budget PQ msig test; gas rows 2-of-2 / 3-of-3 `mldsa65` holder and an `slhdsa128s` fee UA on both relay paths (assert the PQZH n2048 verdicts of the README row C0-2).
- [ ] **Step 2:** Run the registry and `PqzStateGas` suites — FAIL.
- [ ] **Step 3:** Implement the bound of row C0-5 in `_pqzAttr` (worst-case authorization from `_checkMembers`' `worst`); C0-11 as its row.
- [ ] **Step 4:** Suites pass at all four sets; record the bound in `accounts.md` / CTR-PQZ-12.
- [ ] **Step 5:** Commit.

### Task 3: Zether `…/v3` — audited multi with independent auditor randomness (C0-1), `validUntilBlock` (C0-9), `Y_a` as party

**Files:**
- Modify: `smartcontracts/evm/src/zether/ZetherVerifier.sol` (`_psidLabel` → `"scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"`, `_sigmaTransferMulti`, `_sigmaLegs`, `_sigmaLeg`), `ZetherLib.sol` (`_multiStatement`, `_record`, `_auditorPoint`, header with `validUntilBlock`), `ZetherStatements.sol`, `IZetherToken.sol` (errors `AuditorKeyAsParty()`, `TransferExpired(uint256 validUntilBlock)`)
- Modify: `clients/zether-prover/src/zether.rs` (multi prover / verifier, `derive_s` plus a per-leg `derive_t(x, h, from_ua, salt, j)`), `clients/zether-prover/src/api.rs`, `clients/zether-prover/src/vectors.rs`
- Modify: `smartcontracts/evm/test/zether/helpers/ZetherProver.sol`, `ZetherFixture.sol`; vectors `smartcontracts/evm/test/vectors/zether/`
- Docs: `docs/contracts/zether.md` §7 / §9 / §11 (statement, proof layout, E6_j, E6′_j), CTR-ZTH-30 / -37 / -40, decisions

**Interfaces:**
- Produces: multi statement `Y_f Y_a C_acc D_acc D_out C_deb be32(M) (Y_tj C_out_j C_aud_j D_aud_j)_j` (D_aud_j = O when the auditor is off); multi proof adds `A_Daud_j` and `z_tj` per leg; E6_j `[z_vj]G + [z_tj]Y_a − [c]C_aud_j − A_aud_j`, E6′_j `[z_tj]G − [c]D_aud_j − A_Daud_j`; header field `validUntilBlock`, checked `block.number <= validUntilBlock` on every Zether transfer (single and multi), the same rule as the PQZ header's `validUntilBlock`; the `AUDITOR` disclosure of leg `j` uses `D_aud_j`.

- [ ] **Step 1: Failing tests.** `test_multiAudited_decoysDistinct` (two decoy legs → distinct `C_aud`, and `h_k·C_aud_j − h_j·C_aud_k ≠ O` for small public `h`); `test_multiAudited_auditorDecryptsEachLeg`; `test_v2ProofRefused`; `test_auditorKeyAsParty` (`Y_tj == Y_a` or `Y_f == Y_a` with the auditor on reverts `AuditorKeyAsParty`); `test_directTransferExpired`; the Rust tests `multi_audited_roundtrip`, `multi_tampered_d_aud_rejected`, `v2_vectors_refused`.
- [ ] **Step 2:** `scripts/capped cargo test -p zether-prover` and `forge test --match-path 'test/zether/*'` — FAIL.
- [ ] **Step 3:** Implement the layout above in the prover, then the verifier and `ZetherLib`; regenerate the vectors with the prover (`vectors.rs`); the interim `M ≥ 2` refusal is not needed once this lands (do not add it).
- [ ] **Step 4:** Both suites pass; `ZetherVerifierGas` rows updated (ratchet comment); spec and decisions (CTR-ZTH-* Change "owner ruling 2026-10-27, C0-1 (ii)").
- [ ] **Step 5:** Commit.

### Task 4: Zether disclosure — strong Fiat–Shamir (C0-4)

**Files:**
- Modify: `smartcontracts/evm/src/zether/ZetherDisclosure.sol` (`pre`, `_chaumPedersen`), `clients/zether-prover/src/schnorr.rs` (`cp_prefix`, `cp_challenge`, `open_*`, `verify_opening`), disclosure vectors, `docs/contracts/zether.md` §14, CTR-ZTH-40

**Interfaces:**
- Produces: `e = hashToScalar(keccak256(pre ‖ G ‖ K ‖ B ‖ M ‖ A1 ‖ A2))` (points in the curve's encoding), same in Rust.

- [ ] **Step 1: Failing test.** `test_disclosure_lateS_noFalseOpening` (build `s = k1⁻¹(k2 + e(v − a))` against the old challenge; the new verifier refuses the opening for `a`); Rust `cp_challenge_binds_statement_points`.
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** Implement in both; regenerate the disclosure vectors.
- [ ] **Step 4:** Pass; docs.
- [ ] **Step 5:** Commit.

### Task 5: Zether records in state; NONE retired (C0-3)

**Files:**
- Modify: `smartcontracts/evm/src/zether/ZetherLib.sol` (`_storeRecord`: HASH stores `R` by SSTORE2, the slot holds the pointer), `ZetherDisclosure.sol` (read `R` from state; drop the `bundles` argument), `ZetherLayer.sol` / tokens (remove `mtxConfidentialTransferNoBundle`, `OP_MULTI_NONE`; `disclosureMode` NONE refused at `init`), `ITransferDisclosure.sol`, the relay allow-lists, `clients/zether-prover/src/api.rs`
- Test: `smartcontracts/evm/test/zether/ZetherModes.t.sol`
- Docs: zether.md §14, CTR-ZTH-38 / -48 / -50

**Interfaces:**
- Produces: `transferEntry(bytes32 entryRef) returns (bytes memory R)`; `verifyTransferAmount(token, entryRef, index, amount, kind, opening)` without `bundles`; error `IZetherToken.TransferEntryDisabled` no longer reachable for NONE (NONE refused at init with `BadDisclosureMode`).

- [ ] **Step 1: Failing tests.** `test_noBundleRetired`, `test_disclosure_readsRecordFromState`, `test_init_noneModeRefused`, `test_hashRecordMatchesR`.
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** Implement; update the prover's calldata builders.
- [ ] **Step 4:** Zether suites pass; size gate (ratchet comments).
- [ ] **Step 5:** Commit.

### Task 6: Metatx, factory and DEX hardening (C5-1 … C5-5, C6-1, C6-5, C6-9, C0-13, C0-19, C1-2, C1-3)

**Files:** as each README row names (`src/metatx/`, `src/factory/`, `src/common/`, `src/dex/`, `src/trade/`, `script/` deploy gate for C5-1); tests next to the existing ones of each file.

- [ ] **Step 1:** One failing test per row (name `test_<id>_<behaviour>`, e.g. `test_C5_5_bindingClearedAfterSelfCall`, `test_C6_5_nonceAbove2pow128Refused`); C5-1: a deploy-gate check that refuses a release deployment when the chain's block gas limit is below the kind's need (NET-EVM-06 minimum per kind, about 75 M plain / 110 M confidential, regular + state — numbers from the size baseline × 1,530 state gas per byte).
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** Implement each row's fix.
- [ ] **Step 4:** Full forge at `n2304-kmax4096` passes; size gate 0 errors.
- [ ] **Step 5:** Commit.

### Task 7: Node and client items (C3-2, C6-2, C6-3, C6-7)

**Files:** `clients/zether-prover` (C3-2 `uaExecute` gas column), `scaas-node/src/` (C6-2 exchange selectors, C6-3 watcher emitter check, C6-7 `UANoncesInvalidated`).

- [ ] **Step 1:** Failing unit test per row in the crate's existing test module.
- [ ] **Step 2:** `scripts/capped cargo test` in each crate — FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Pass.
- [ ] **Step 5:** Commit.

### Task 8: Spec and doc fixes ((c) list, C0-6, C0-10, C0-18, C2-5)

**Files:** the documents each (c) row names; `docs/contracts/pq-zero-knowledge.md` CTR-PQZ-08 (a), T7, T8, redesign spec §5.6 (C0-6: accept — the attack, its cost, wallets re-prove on `PendingRange`); C0-10 client rule M ≤ 4 where the block limit is 60 M; C0-18 the native-coin `mtxWrapShield` exception (decisions + metatx.md); C2-5 (no outer-fee pre-check; `shieldIn` pull only); `docs/decisions.md` Change lines for every ruling and controller proposal of this plan.

- [ ] **Step 1:** Edit; `python3 -I scripts/docs_check.py check` 0 errors.
- [ ] **Step 2:** Commit.

### Task 9: Gates (one step per log, resumable — owner 2026-10-27)

**Files:**
- Create: `smartcontracts/evm/runs/2026-10-27-review2-gates.sh` — runs the steps below in order; each step writes `smartcontracts/evm/runs/2026-10-27-review2-<step>.txt` whose first line is `# <step> at commit <sha>` and last line `rc=<n>`; a step whose log exists with `rc=0` at the current commit (`git rev-parse --short HEAD`, tree clean) is skipped; `GATES_FRESH=1` re-runs all; `--only <step>` runs one. Steps never edit tracked files (`at-set.sh` restores `PqzSet.sol` itself).

**Steps (names = log names):**
`forge-n2048-kmax1024`, `forge-n2304-kmax4096`, `forge-n2560-kmax16384`, `forge-n2816-kmax65536` (each `scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test`), `sizes` (size gate at the committed set), `gen-set` (`gen_set.py --all --check`), `docs` (`docs_check`), `cargo-zether-prover` (`cargo test -j2` in `clients/zether-prover`), `wasm-zether-prover` (rebuild the git-ignored `pkg/` and run `smoke/smoke.cjs`), `cargo-scaas-node` (`cargo test -j2` in `scaas-node`).

- [ ] **Step 1:** Write the script; run `--only docs` twice — the second run prints `skip docs (rc=0 at <sha>)`.
- [ ] **Step 2:** Run the script (resume by running it again after any stop).
- [ ] **Step 3:** Commit the script and the logs; add a "Fix round" section to the review README (per finding: done / commit / test, the gate logs), commit.
