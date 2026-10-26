# Security Review Report: Unit R1 — Transcript / Fiat–Shamir (Code)

**Target:** SCaaS Repository (`pqz-core/` at commit `008e196c`)  
**Scope:** Unit R1 — Fiat–Shamir transcript construction, message absorption, and challenge derivation in PQZL (C core + Rust port, generic verifier + specialised verifier) and PQZH (Ligero in Rust).  
**Mode:** Strictly Read-Only (Static Analysis & Code Verification).  
**Parameter Sets:** `n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`, `n2816-kmax65536` (no PQZH at `n2816-kmax65536`).  
**Relations:** `R_REG`, `R_DS` / `R_DR`, `R_TX`, `R_TX0`, `R_BURN`, `R_TXM M = k`.

---

## Executive Summary

Unit R1 audits the Fiat–Shamir transform and transcript binding across all production proof paths in PQZL and PQZH. The primary focus of this review was verifying whether prior critical soundness vulnerabilities (specifically **B-1 / A-1** regarding challenge ordering, and **A-2** regarding Schwartz–Zippel domain collisions) were correctly and completely resolved in commit `4adea55c` (5h Task 8a), verifying that no challenge sets share PRG domains, ensuring that all public statement components (including `proofSystemId` and the `R_REG` message) are securely absorbed, and confirming strict transcript equivalence between the C and Rust implementations across generic and specialised verifiers (`SV`).

**Verdict:** The live production code (`lnp-tbox.c`, `pqz_sv.c`, `pqz_rel.c`, `proof/{tbox,quad,abdlop}.rs`, `sv.rs`, `coder.rs`, `transcript.rs`) is **sound** with respect to all four target invariants. The B-1 fix correctly draws $V_3 / V_4$ from `hash1` (after $t_g$), eliminating the linear cancellation attack through $g$. The A-2 domain collision between $\beta_4$ and $\upsilon$ has been completely resolved by shifting subsequent Schwartz–Zippel domains up by one. Statement hashing universally binds the statement prefix (`opTag ‖ proofSystemId`), statement length, parameters, and the 32-byte `R_REG` message into the initial transcript state. C and Rust generic and specialised verifiers display exact algorithmic parity in transcript sequencing, serialization, domain indices, and challenge generation.

One minor hygiene finding (**R1-1**, severity **P3**) is reported: the dead upstream file `pqzl/lazer/lnp-quad-eval.c` was never patched with the $h$-before-$\mu$ absorption fix, though it has zero callers in SCaaS.

---

## Findings

### R1-1 — P3 (Dead Code / Upstream Hygiene) — Unused upstream evaluator `lnp-quad-eval.c` omits message $h$ absorption before $\mu$

- **File & Lines:** `pqz-core/pqzl/lazer/lnp-quad-eval.c:453, 603–606, 674, 749–755`
- **Claim:** In the unused upstream LaZer fork file `lnp-quad-eval.c`, prover message $h$ is not absorbed into the Fiat–Shamir transcript before calling `lnp_quad_many_prove` / `lnp_quad_many_verify` (which derives $\mu$ and subsequent challenge $c$). Additionally, challenge matrix $v$ is derived at line 453/674 using `intmat_urandom (v, q, log2q, hash, 0)` under domain 0, which coincides with domain 0 used for evaluation equations.
- **Evidence:**
  In `pqz-core/pqzl/lazer/lnp-quad-eval.c:603-606`:
  ```c
  _lnp_quad_eval_prove (hash, tB, h, s1, m, s2, Bprime, R2i, r1i, Rprime2i,
                        rprime1i, M, seed_tbox, params);
  lnp_quad_many_prove (hash, tB, c, z1, z21, hint, s1, m, s2, tA2, A1, A2prime,
                       Bprime, R2prime_sz, r1prime_sz, lambda / 2 + 2 + N,
                       seed_cont2, quad);
  ```
  And in `lnp-quad-eval.c:749-755`:
  ```c
  b = _lnp_quad_eval_verify (hash, h, tB, R2i, r1i, r0i, Rprime2i, rprime1i,
                             rprime0i, M, params);
  if (b != 1)
    goto ret;

  b = lnp_quad_many_verify (hash, c, z1, z21, hint, tA1, tB, A1, A2prime,
                            Bprime, R2prime_sz, r1prime_sz, r0prime_sz,
                            lambda / 2 + 2 + N, quad);
  ```
  In production `lnp-tbox.c:806, 1351`, the call `_lnp_tbox_hash_h (hash, h, params);` was inserted before `lnp_quad_many_prove` / `lnp_quad_many_verify` to close the Review C / lazer#28 vulnerability. `lnp-quad-eval.c` does not include `_lnp_quad_eval_hash_h`.
- **Reasoning & Impact:**
  `lnp_quad_eval_prove` and `lnp_quad_eval_verify` have zero callers anywhere in `pqz-core/` or `scaas-node/` (SCaaS relations compile and verify exclusively against `lnp-tbox.c`). Hence, this has zero exploitability or consensus impact on the production SCaaS system. However, keeping unpatched cryptographic routines in `lazer/` creates a latent trap if code is repurposed or exposed.
- **Suggested Fix:**
  Either delete `lnp-quad-eval.c` and its prototypes in `pqz-core/pqzl/lazer/lazer-in2.h:1464, 1474`, or insert `_lnp_quad_eval_hash_h` before `lnp_quad_many_prove` and `lnp_quad_many_verify`.

---

## Checked and Sound

Every required security invariant was verified across all implementations in scope:

1. **Every challenge is drawn after every message it must bind (z3 / z4 / h / tg — the B-1 class):**  
   *Evidence:* In both provers and all four verifiers (`lnp-tbox.c:703, 1292`; `pqz_sv.c:1598, 1649`; `tbox.rs:729, 808`; `sv.rs:1397, 1453`), $V_3 / V_4$ and $\gamma$ are sampled from `hash1` ($H(\text{hz} \parallel \text{urandom3}(t_g))$), ensuring $t_g$ and $z_3, z_4$ are committed before $V_3, V_4$, while $h$ is absorbed into `hash2` ($H(\text{hash1} \parallel \text{urandom3}(h))$) before $\mu$ (`lnp-tbox.c:806`, `tbox.rs:813`, `pqz_sv.c:1549`, `sv.rs:1340`) and $(t, v, w_1)$ are absorbed before $c$ (`lnp-quad.c:241, 490`; `quad.rs:141, 305`; `pqz_sv.c:1952`; `sv.rs:1742`).

2. **No two challenge sets share a domain (A-2):**  
   *Evidence:* In commit `4adea55c`, $\upsilon$ was relocated to $M + 2(d-1) + 1 = M + 127$ (preventing collision with $\beta_4$'s row 63 at $M + 126$), binary to $M + 128$, exact-$\ell_2$ block $i$ to $M + 129 + i$, $V_4$ to $M + 129 + Z$, and $V_3$ to $M + 385 + Z$ (`lnp-tbox.c:670–714, 1262–1302`; `pqz_sv.c:1646, 1763–1769`; `tbox.rs:675–734`; `sv.rs:1446, 1573–1580`), with $V_4 / V_3$ further separated by nonces with $dom \ge 2^{32}$, yielding zero shared domains across all 129 calls in `check_tbox_fixes.sh` and across all relations for any $M \ge 0, Z \ge 0$.

3. **The statement, the proofSystemId and the `R_REG` message enter the transcript:**  
   *Evidence:* In PQZL, `pqz_stmt_hash` (`pqz_rel.c:312–315`) and `stmt_hash` (`rel.rs:167–171`) compute $\text{SHAKE128}(\text{"SCAAS-PQZ-TRANSCRIPT-V1"} \parallel op \parallel \text{be32}(len) \parallel stmt)$ over the entire statement buffer (which begins with $opTag$ at bytes 0..31, $proofSystemId$ at bytes 32..63, and the 32-byte registration message at bytes 64..95 for `R_REG`), while PQZH seeds Keccak-256 state with $\text{keccak256}(\text{"SCAAS-PQZH-LIGERO-V1"} \parallel op \parallel \text{be32}(len) \parallel stmt)$ (`transcript.rs:16–19`), guaranteeing strong Fiat–Shamir binding across both proof systems.

4. **C = Rust (both cores, generic and specialised verifiers):**  
   *Evidence:* Generic C (`lnp-tbox.c`, `lnp-quad.c`, `pqz_rel.c`) and generic Rust (`tbox.rs`, `quad.rs`, `rel.rs`, `abdlop.rs`), as well as C SV (`pqz_sv.c`) and Rust SV (`sv.rs`), execute byte-identical transcript rounds (SHAKE128 absorb/squeeze sequences, canonical `urandom3` and `grandom3` serializations in `coder.c` / `coder.rs`, identical PRG nonces and sampling orders), confirmed by 0 mismatches across 4,524 differential SV test runs and exact verdict agreement across 2,828 extreme/mutated cases.

---

## Not Covered

Per the strict read-only scope instructions, the following subsystems were not analyzed:
1. **Underlying Arithmetic & NTT Implementation Details:** `pqz-core/pqzl/lazer/int*.c`, `poly*.c`, and `pqzl/rust/src/arith/*` beyond the bounds and reduction calls directly involved in Fiat–Shamir serialization.
2. **Prover Witness Generation & Key Derivation:** Witness generation algorithms in `pqzl/rust/src/keys.rs` and `pqz_keys.c` (outside transcript verification).
3. **Solidity Contracts & Precompile Node Integration:** The Nethermind plugin (`scaas-node/`) and EVM contracts (`smartcontracts/`) were not reviewed in this unit.
4. **Non-Ligero Backup Proof System:** `pqzh/stark-backup/` and `pqzh/xcheck/` (not live in the active confidential payment path).
5. **Sage Parameter Derivations & Tail Bound Estimations:** `pqz-core/params/codegen/` scripts and lattice security estimators were not re-executed or audited.
