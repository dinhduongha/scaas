# pqz-core review 3w — fix round (branch `pqz-3w-fix`)

> Research record, not a rule. The rules changed by this round are in `docs/decisions.md` (CTR-PQZ-04, CTR-PQZ-09,
> CTR-PQZ-10 entries of 2026-11-13). Everything here is UNAUDITED.

Reviews: Fable 5.2 (u1–u5) and Codex gpt-6.1-sol (u1–u4) at `ua-mtx-merge` `cac043bc`; the triage ids T-01 … T-41 and
the reports are kept outside the repository. This round fixes the class (a) items; T-01 (OFFCHAIN decryption-failure
oracle) is an owner-ruled separate design, T-17, T-35, T-36 wait for the owner, T-18's calibration run needs the owner's
go.

## Negative controls and mutants

Each guard or check removed alone (sources restored after each run); "red" = the named test fails.

| Item | Control | Result |
|---|---|---|
| T-02 | `gate-controls.sh`: stub tools, a failing `cargo test` / build / clippy / bench, a test hook in the cdylib, `native != wasm32`, fuzz rc 77, a `FINDING` line, an unknown vector file | new scripts: 12 / 12 controls right; the pre-fix `ffi/run.sh` and `fuzz/run.sh`: 8 failures exit 0 |
| T-04 | `ct.sh` with a secret-dependent branch planted in `pqz_prove` (C) and `Ctx::prove` (Rust), n2048-kmax1024, R_REG | 1 report each side, rc 1; unmodified: 0 reports, rc 0 |
| T-05 | `pqz-vectors --check` with an unknown `bogus.json` | `EXTRA`, FAIL; `state.json` reported `OTHER` |
| T-15 | the pre-fix `replay_wasm.mjs`, C backend, n2816-kmax65536 | M2-on / M4-on proof 0 B, rc 1; new: 32 cases, 9 verify-only with the prover's refusal, 0 fails |
| T-03 | PoW, linear sum, proximity, per-column linear, quadratic check each disabled | `every_check_decides_a_cheat` red each time |
| T-10 | linear sum check disabled | `disclose_auditor_every_window` red |
| T-08 | Rust `polyvec_grandom` guard removed; C guard (ERR and return) removed | `grandom_eq_c` red (Rust ≠ C) |
| T-13 | Rust `enc_seed` guard; C `pqz_enc_seed_win` guard; `enc_multi` guard | `enc_seed_refuses_an_equal_key_at_an_equal_window` red (Rust, C); `enc_multi_refuses_equal_keys` red |
| T-12 | `pqz-ffi` back on Ligero's catching `try_verify` | `fault.rs` red (status 0, not 3) |
| T-31 | the SV headroom assertion tightened to 2^10 | does not compile |
| T-11 | tA1 not absorbed (prover and verifier); w1 not absorbed (prover and verifier); kind-4 trace removed | `fs_bind_commitment_r_and_final_seeds` red |
| S4 | generator mutants M1, M5, M6, M7, header and `codegen.txt` tamper, `log2stdev` 24 | new `gen_set.py`: write and / or `--check` rc 1; HEAD's: rc 0 for M6, M7 and both tampers |
| S5 | ML-DSA catch removed; genesis schedule skip at 0 only | `Another_exception_is_a_node_fault` red; `A_schedule_at_a_nonzero_genesis_timestamp_is_no_transition` red |

## Gate

Filled in at the end of the round (S7).
