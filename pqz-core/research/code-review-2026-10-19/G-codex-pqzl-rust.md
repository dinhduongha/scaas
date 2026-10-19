# G — Codex review of the PQZL Rust crate (second model)

**Date:** 2026-10-19. **Reviewer:** Codex CLI 0.163.0 (one read-only task; owner-requested, plan
`docs/superpowers/plans/2026-10-19-pqzl-fs3.md` Task 11 second-model note). **Target:** `pqz-core/pqzl/rust/` at
`0dc869d` (branch `pqzl-fs3`: Fiat–Shamir fix lazer#28, proofSystemId v3, D-2 Rej1, D-3 β signs), frozen worktree.
Scope: verification soundness, panics from input, wasm32 vs native, allocation failure, `unsafe` / feature leakage,
prover side channels and wiping. No builds, tests or timing runs. A first attempt failed before reading any file
(Codex 0.163 sandbox vs AppArmor `apparmor_restrict_unprivileged_userns`; fixed with `/etc/apparmor.d/bwrap-userns`).

Disposition (controller) is recorded in the triage section below once agy's parallel review (H) is in.

## Findings (Codex's text, condensed)

1. **P1 — prover control flow depends on secret witness values (side-channel exploit: hypothesis).**
   `rust/src/rel.rs:774–787`, `rust/src/arith/poly.rs:365–368`, `rust/src/arith/int.rs:279–307`. `set_upsilon`
   computes the secret slack `B² − ‖x‖²`; `binexp` conditionally subtracts and writes a coefficient per set bit, so
   the branch / write pattern encodes the slack's binary expansion; `Int` add / sub branch on signs and borrow.
   Impact: an observable branch trace reveals witness-block norms; exploitation through native / browser timing not
   demonstrated. Inherited from C (`lazer/int.c:257–266`). Fix: write every slack coefficient from its bit without
   conditional writes; constant-time sign / magnitude arithmetic on secret paths; check generated native and wasm code.
2. **P2 — explicit secret copies and mask seeds not wiped (confirmed).** `rust/src/proof/tbox.rs:1062–1079`, `:1131`,
   `rust/src/proof/quad.rs:228–248`, `rust/src/rel.rs:917–922`. `tbox::prove` expands a 96-byte secret seed and copies
   `s1` into `sv`; the lower prover copies it again into `s` and creates `yseed`; no zeroizing destructor; the outer
   cleanup wipes `ex0`, `ex1`, `s1`, `s2` only. Impact: witness material and mask seeds stay in freed heap / stack
   (needs a memory-read capability; no transcript leak). Fix: zeroizing drop guards on secret-owned buffers and seeds,
   covering every `?` exit.
3. **P2 — oversized statements hashed before the length check (confirmed; direct crate API only).**
   `rust/src/rel.rs:864–869`, `:138–141`, `rust/src/sv.rs:1757–1771`, `:996–1011`. `OP_REGISTER` with an arbitrarily
   large statement and an empty proof: the whole statement enters SHAKE (and cold caches initialise) before the fixed
   length is checked; work proportional to the statement length. Same order in C (`src/pqz_rel.c:1364–1369`,
   `1397–1398`). The production FFI's `MAX_INPUT` check bounds it (`pqz-core/ffi/src/lib.rs:87`); no precompile
   bypass. Fix: check the relation's exact statement length and the proof cap before cache initialisation and hashing.

## Checked and clean (Codex)

- **Fiat–Shamir change:** both verifiers absorb z3 / z4 after the norm checks, keep the JL rows on `cseed`, absorb h
  before μ and the final challenge (`proof/tbox.rs:775–805`, `sv.rs:1315–1355`, `sv.rs:1737`; C
  `lazer/lnp-tbox.c:2024–2118`); early verifier returns reject, never resume a partial transcript.
- **Norms:** z1, combined `(z21, w − γ·w1)`, z3, z4, hint, separate l2 domains (`proof/quad.rs:145–163`,
  `proof/tbox.rs:297–309, 690–709`, `sv.rs:1309–1355, 1739–1745`; C `lazer/lnp-quad.c:514–517`,
  `lazer/lnp-tbox.c:3256–3258`).
- **Decoder:** bounded reads, fixed-width range checks, unary termination, padding and trailing-byte rejection
  (`coder.rs:180–293`); with the current parameters and the proof cap, Gaussian coefficients stay below q/2 (no
  reduction aliases) and hints below the smallest m/2.
- **Arithmetic / wasm32:** no overflow in the SV accumulators, JL folds, CRT reductions, norm sums
  (`sv.rs:152–175, 285–324, 360–423, 610–645, 1222–1236`); bounded u128 accumulators in the NTT products
  (`arith/ntt.rs:95–106`).
- **Allocation / features:** production growth sites reserve fallibly; no input-reachable `unwrap` / `expect`; default
  features exclude the oracle, bench and tracing code; `unsafe` forbidden outside `c-oracle` (`lib.rs:6–42`).
- **D-2 / D-3:** `rej_onetime` uses σ2 and the standard draw; β signs consume successive bits (`proof/quad.rs:315–324`,
  `rand/rejection.rs:106–110`, `proof/tbox.rs:945–972`); match the C changes.

## Not checked (Codex)

Builds, tests, fuzzing, exhaustive allocation denial (`tests/memory.rs` samples by default), generated assembly,
timing measurements, dependency internals, an independent soundness proof.
