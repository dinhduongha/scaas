# Whole-core review 2026-10-25 (plan 5h Task 9 independent review: pqz-core, the precompile, the cryptography)

**Request (owner 2026-10-25).** Re-review all of `pqz-core` and the precompile, because much changed since the reviews
of 2026-10-19 / -20 ([../code-review-2026-10-19/README.md](../code-review-2026-10-19/README.md), at one parameter set and
the retired ids): three independent reviewers — **Codex** (GPT), **agy** (Gemini) and a **Claude Code workflow at
UltraCode effort** — plus a separate **cryptographic design review**. The contracts (8d part 2) get one Codex pass after
2a and 2b, not here.

**Target:** frozen detached worktree `.claude/worktrees/review-2026-10-25` at `pqz-16k` **`008e196c`** (the core is
soft-frozen: changed only if this review or the Task 9 60 ms check requires it). Read-only for every reviewer: no
builds, no tests, no timing runs, no commits.

**What changed since the last review** (`c173de37` → `008e196c`, code only): PQZL C + LaZer fork +371 / −326 lines,
PQZL Rust +544 / −3,404 (parameter tables now generated per set), PQZH Ligero +898 / −204, `pqz-stmt` +238 / −69,
`pqz-ffi` +368 / −166, Nethermind plugin +90 / −37. In content: the B-1 / A-2 transcript fixes; new parameters for
three sets (q, NTT constants, bit widths, norm bounds, `K_MAX` overflow margins); `R_REG` bound to the UA id; Ligero on
the new fields with radices 7 / 17 and per-set presets (`t`), wasm32 limbs; per-set `MAX_INPUT` / ids in pqz-stmt and
pqz-ffi; `n2816-kmax65536` without PQZH.

## Units

| Unit | Scope (paths under `pqz-core/`) | Invariants to check |
|---|---|---|
| **R0 — cryptography (design)** | `docs/superpowers/specs/2026-10-20-pqz-state-redesign.md` §6, `docs/research/pqz-tbox-soundness.md`, `pqz-core-e-s1.md`, `pqz-parameters-e-s0.md`, `pqz-anonymity.md`; `params/sets/*/{set.toml,SET.md,e-s0.txt,e-s1.txt,codegen.txt,*_params.sage,PQZH.md}`, `pqzl/params/aprime/`, `pqzh/ligero/ligero_params.py` | the relations (R_REG, R_DS / R_DR, R_TX, R_TX0, R_BURN, R_TXM M = k) prove what the spec says (balance conservation, range, key ownership, `R_REG` bound to the UA); knowledge soundness of the LNP22 / LaZer proofs at each set (MSIS / MLWE hardness ≥ the 450 target in uSVP **and** dual_hybrid; the soundness error of every challenge, Schwartz–Zippel included); zero knowledge (Rej1 for z2, the bimodal z3 / z4, the hints leakage with DDGR20 worst cases, the shared randomness of R_TXM groups); encryption (MLWE / BFV-additive correctness: no decryption failure after `K_MAX` additions; key / encryption β); Ligero (field size, rate, `t`, proven soundness bits ≥ the stated target, zero knowledge); the `n2816-kmax65536` no-PQZH reasoning |
| **R1 — transcript / Fiat–Shamir (code)** | `pqzl/lazer/lnp-tbox.c` (+ `lnp-quad*.c`), `pqzl/src/pqz_sv.c`, `pqzl/src/pqz_rel.c`, `pqzl/rust/src/proof/{tbox,quad,abdlop}.rs`, `pqzl/rust/src/sv.rs`, `pqzl/rust/src/coder.rs`, `pqzh/ligero/src/transcript.rs` | every challenge is drawn after every message it must bind (z3 / z4 / h / tg — the B-1 class); no two challenge sets share a domain (A-2); the statement, the proofSystemId and the `R_REG` message enter the transcript; C = Rust (both cores, generic and specialised verifiers) |
| **R2 — parameters per set (code)** | `params/sets/gen_set.py`, `params/sets/<set>/` for all four sets, `pqzl/src/pqz_ntt.c`, `pqzl/rust/src/arith/`, `pqzl/rust/src/params/`, `pqzl/src/pqz_keys.c`, `pqzl/rust/src/keys.rs` | the generated headers equal the reviewed parameters (q, Δ, NTT roots, bit layouts M 18 / carries 15 / `e_T` 29 at the new sets, norm bounds, `K_MAX`); no integer overflow in any limb / accumulator at any set (log2 q up to 54, the C core's `PQZ_LOG2Q ≤ 56`); keygen / Enc / Dec agree with the spec |
| **R3 — PQZH Ligero (code)** | `pqzh/ligero/src/{fq,fft,ligero,cs,client,merkle,ring,ct,set}.rs`, `params/sets/*/pqzh_set*.rs` | field arithmetic correct at every PQZH q (native u128 and the wasm32 limb split); FFT domains (radices 2 / 7 / 17 / 19 / 43 / 431) and the `GEN·H_n ∩ H_k = ∅` condition; the verifier's checks complete (degree, linear, quadratic, Merkle); soundness bits per preset `t`; native = wasm32; the prover's constant-time paths (review O) still hold |
| **R4 — the precompile surface (code)** | `stmt/src/`, `ffi/src/` (C ABI, `pqz_precompile`, `pqz_max_input`, self-test, PQZH dispatch / none), `ffi/pqz_ffi.h`, `nethermind/Nethermind.Pqz/` | never crashes or panics on any input; length / `MAX_INPUT` / `MAX_PROOF(id)` checks before any work; retired and other sets' ids refused; the result is 32 bytes 0 / 1 only; gas per schedule row; addresses; the self-test and the library hash pin; arena / allocation bounds |

## Reviewers

- **Codex** (Codex CLI 0.163.0; sandbox checked 2026-10-25 with `codex sandbox`: `bwrap-userns (unconfined)`): one
  read-only task per unit, **one at a time** (owner rule: limited credits): R1 → R2 → R3 → R4 → R0. Output verbatim in
  `<letter>-codex-<unit>.md`.
- **agy** (Gemini): the same five units, in parallel. Output in `<letter>-agy-<unit>.md`.
- **Claude Code workflow (UltraCode)**, Claude Opus 5.5, per unit: (1) finders in parallel by lens — soundness,
  arithmetic / overflow, input safety / no-crash, determinism and cross-implementation agreement, spec conformance;
  (2) every finding challenged by three independent refuters, kept only if a majority cannot refute it with file:line or a
  test argument; (3) further finder rounds until two rounds in a row add nothing; (4) a completeness critic ("which file
  or invariant was not read or checked?") whose gaps become another round. Output `<letter>-claude-<unit>.md`.
  Independence comes from fresh context and the refutation rounds (same model family as the implementers); Codex and
  agy supply the different models.

## Consolidation (controller)

Merge the three sources per unit, drop duplicates, have every finding that only one model reported checked by another
model, and write the result table here (severity P0–P3, file:line, evidence, fix, status) with the triage for the fix
round. The findings feed plan 5h Task 9 ("independent review of the parameter and transcript change"); fixes in the
core are made only for confirmed findings, then the affected gate steps re-run (full gates if core code changes).

## Results

**Interim (2026-10-25; the Claude UltraCode pass is still running; nothing below is triaged yet except R0-1).** Raw
outputs: `codex-R*.md`, `agy-R*.md` (local absolute paths stripped); the prompts `prompt-R*.txt`.

| Id | Sev. | Source | Finding | Status |
|---|---|---|---|---|
| R0-1 | **P1** | Codex (agy: not found) | R_TXM auditor copies of a group share `pk_a`, `r_g` and 16 coefficients: their differences reveal every digit difference of the legs (decoys identifiable) — [R0-1-auditor-shared-randomness.md](R0-1-auditor-shared-randomness.md) | **confirmed** by the controller; owner: fix direction 2, hint study first |
| R0-2 | P3 | Codex | E-S0's soundness gate uses a computed Schwartz–Zippel repetition count, not λ read from the generated parameters | to verify |
| R0-a | P3 | agy | `pqzl/params/aprime/` research sizing specs omit `kmlwe_min = 42` (sub-450 dual_hybrid in the stale scripts) | to verify |
| R1-1 | P2 / P3 | Codex P2, agy P3 (agree) | `lnp-quad-eval.c` (`lnp_quad_eval_verify`, not on the PQZ path) still derives μ without absorbing `h` | to verify reachability; patch or remove |
| R2-a | P3 | agy | stale set constant in relation-reconstruction comments; `bb[0]` uninitialised in `basemul16` | to verify |
| R3-1 | P3 | Codex, agy (agree) | the `fallback-retry` preset (experimental, off by default) keeps the production proofSystemId | to fix (own id or remove) |
| R4-a | P3 | agy | `ExpectedLibrarySha256` not per set (known: review 8d1b M4); stale retired-id table row in the spec; `pqz_ffi.h` comment omits n2816 | to verify / docs |
| R4-b | note | Codex | "never crashes" holds except allocation abort, documented in `pqz_ffi.h` | note |
