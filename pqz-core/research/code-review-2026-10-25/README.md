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

**Consolidated 2026-10-25** (four reviewers done: Codex, agy, Claude UltraCode — 350 agents, three-vote refutation —
and Fable on R0 as adjudicator). Raw outputs: `codex-R*.md`, `agy-R*.md`, `claude-R*.md`, `fable-R0.md`; prompts
`prompt-R*.txt` (local absolute paths stripped). Severity = the adjudicated one.

**Fix in the next proofSystemId bump (core change):**

| Id | Sev. | Found by | Finding | Status / fix |
|---|---|---|---|---|
| R0-1 = R0-C1 = F-1 | **P1** | Codex, Claude, Fable (agy missed) | audited R_TXM: auditor copies of a group share `pk_a`, `r_g` and the coefficient → digit differences public | owner: direction 2, `s_aud` 2 / 3 / 4 / 4 — [R0-1 note](R0-1-auditor-shared-randomness.md); Fable: design sound, four required additions (below) |
| R0-C2 = F-2 | **P2** | Claude, Fable | z4 bimodal rejection in R_REG / R_DR / R_DA sized with `Bprime = 1` (read as ℓ∞) while `s4 = s[0]` has ℓ2 ≈ 5.7 → z4 not D_σ4, slow leak of `s[0]` over many proofs of one key (R_DA repeats) | `Bprime = 8` (ℓ2 bound) in reg / dr specs, +96 B per proof; codegen assertion; same id bump |
| R0-C3 = F-3 | P3 | Claude, Fable | the final challenge `c` is never filtered to ‖c‖ ≤ η = 140; ≥ 0.71 % fall outside the set the knowledge error is stated for (no attack) | resample `c` from (cseed, counter) until the η test passes, prover and all verifiers, same id bump — or re-derive B |
| F-4 | P3 | Fable | the auditor UA as sender or as a recipient leg collides masks (before and after the R0-1 fix) | contract: refuse `fromUA == auditorUA` and `auditorUA ∈ legs` when `auditorOn` |

**Required additions to the R0-1 fix (Fable):** (1) the auditor disclosure R_DR kind AUDITOR (R_DA) decrypts at
coefficient `16·(j mod s_aud) + i` → the disclosure statement needs the offset (a new word or folded into `kind`):
pqz-stmt, `PqzCore.disclosureStatement`, provers / verifiers, vectors; (2) the group map `g(j) = ⌊j / s_aud⌋` (auditor on)
/ `⌊j / 4⌋` (off) everywhere (`pqz_rel.c` shapes, `pqz.h` `PQZ_TXM_GROUPS`, pqz-stmt, `PqzCore._legOf`, `cs.rs`, `sv.rs`,
the Enc group seeds, the auditor's Dec) — new R_TXM shapes need codegen / e-s1 / e-s0 runs and `MAX_PROOF` checks;
(3) state in SET.md / CTR-PQZ-04 that `s_aud` at n2304 rests on the dual_hybrid − offset heuristic with a 3-β margin;
(4) F-4's contract rule.

**Fix without an id bump (tooling, docs, robustness), triage in the fix brief:** R0-2 = R0-C7 = F-5 (e_s0 certifies a
computed λ = 3, headers use 4), R0-C4 / F-6 (n2048 exception text: dual figure now measured), agy R0-a / F-7 (aprime
specs lack `kmlwe_min`), R1-1 = R1-C7 (dead `lnp-quad-eval.c` without the `h` fix — remove or patch), R3-1 = R0-C15 =
R3-C1 / R4-C5 (`fallback-retry` keeps the production id — own id or remove; pqz-ffi guard), R2-C3 (KeyGen without set
separation), R1-C1 / R2-C2 (n2048 Power2Round edge), R1-C2 / R4-C1 / R4-C2 (C prover arena sized from n2048),
R4-C3 (start-up does not check schedule ids against the library's ids), R4-C4 (no ML-DSA known-answer test at
start-up), R2-C1 / R1-C12 (`LOG2Q ≤ 56` guard vs correctness up to 55), R2-C4 (`PACK_BITS` by float log2), R2-C8
(e_s1 output overwritten on a failed run), and the remaining P3 / P4 documentation items of `claude-R*.md` / `agy-R*.md`
(n2048-only constants in comments and the spec's serialization section, retired addresses in a README, etc.).

Interim table (Codex + agy only, superseded by the above):

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
