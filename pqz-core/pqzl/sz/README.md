# sz and l2dom: the LaZer tbox soundness fixes (proofSystemId v2, v3)

PQZL, the lattice proof system of PQZ, is a fork of IBM's LaZer library. We found two soundness bugs in LaZer's proof
toolbox (`tbox`, in `lazer/lnp-tbox.c`): in both, a cheating prover had more room than the proof claims. This folder
(`sz/`) and its sibling `l2dom/` hold the test programs that show each bug and check that the fork fixes it; reviewers
and the release checks use them. Background: the parent [pqz-core README](../../README.md), §3
["Two proof systems, one precompile"](../../README.md#3-two-proof-systems-one-precompile).

Paths below are relative to `pqz-core/pqzl/` unless they start with `pqz-core/`.

## The two findings

Both are **Schwartz–Zippel** checks. Instead of checking many polynomial equations one by one, the verifier combines
them with random challenges and checks the combination; a cheater who breaks one equation is caught unless the random
challenges happen to cancel the error. That only works if the challenges are independent and every equation gets its
own. The LaZer maintainers confirmed both findings, and they are public as
[lazer-crypto/lazer#24](https://github.com/lazer-crypto/lazer/issues/24) and
[#25](https://github.com/lazer-crypto/lazer/issues/25). Both are fixed in the fork (look for the `PQZ (P6-SZ)` and
`PQZ (P6-L2)` comments in `lazer/lnp-tbox.c`).

- **P6-SZ (#24).** `__schwartz_zippel_accumulate2` drew one challenge pair and reused it for all λ/2 accumulator pairs,
  so the proof made 2 independent tests instead of λ = 4. Fix: the full λ × M challenge matrix, with rows 2i / 2i+1
  for pair i.
- **P6-L2 (#25).** `__schwartz_zippel_accumulate_l2` gave every exact-ℓ2 equation (a bound on the length of one block
  of secret values) the same domain, so only the sum of the block norms was checked. Fix: domain `dom + i` for
  equation i.

Together the two fixes change the proof transcript, so proofs made before and after are not compatible. That is why
the proof-system id moved to **`proofSystemId` v2** (`src/pqz.h`, pq-zero-knowledge.md §8).

## The third finding: the Fiat–Shamir transcript (P6-FS, lazer#28, v3)

A whole-code review (2026-10-19, `pqz-core/research/code-review-2026-10-19/`) found that LaZer's tbox transcript does
not absorb two prover messages before the challenges that check them: `z3` and `z4` (the approximate-range
responses) before the matrices V3 / V4 that fold their equations, and `h` before `μ` and the final challenge. A
prover that sees a challenge before it fixes the message is not bound by the check. Public as
[lazer-crypto/lazer#28](https://github.com/lazer-crypto/lazer/issues/28). Fixed in the fork (`PQZ (P6-FS, lazer#28)`
in `lazer/lnp-tbox.c`, `src/pqz_sv.c` and the Rust crate): `hz = SHAKE128(cseed ‖ grandom3(z3) ‖ grandom3(z4))` seeds
V3 / V4 (the JL rows R / R' stay on `cseed`), and `hash2 = SHAKE128(hash1 ‖ urandom3(h))` seeds `μ` and the final
challenge. Another transcript change, so **`proofSystemId` v3**; v2 is retired (pq-zero-knowledge.md §8,
`docs/research/pqz-tbox-soundness.md` §8).

## Harnesses

- **Challenge trace** — `sz/sz_trace.c`, `sz/build.sh`: one honest `R_REG` prove with the `-DPQZ_SZ_TRACE` hook in
  `lnp-tbox.c`. For each transcript domain it reports whether the four evaluation-step challenge rows are distinct. It
  exits 0 only if they are.
- **Cheating prover** — `l2dom/l2dom_poc.c` (`R_REG`), `l2dom/l2dom_tx.c` (`R_TX`, a sender with a colluding
  recipient), `l2dom/build.sh`. The cheating prover (`set_upsilon` in `src/pqz_rel.c` under `-DPQZ_L2DOM_POC`) pools
  the slack: some blocks are above their own ℓ2 bound while the sum stays within the pooled budget. `l2dom/build.sh`
  builds it twice:
  - on a copy of `lnp-tbox.c` with the P6-L2 fix undone — the control: its verifier must **accept** the cheating
    proofs;
  - on the real tree — the production `libpqz.a` must **reject** them.
- **Fiat–Shamir binding test (P6-FS)** — `sz/fs_bind.c`, built by `sz/build.sh` next to `sz_trace` (the same
  objects, `pqz_rel.c` / `pqz_sv.c` also with `-DPQZ_TEST_HOOKS -DPQZ_SV`). It proves one honest `R_REG` with a fixed
  `rnd32` and makes three re-encodings of it with one field changed (`pqz_test_mutate`, r1 = 0, r2 = 0x105: poly 0,
  coefficient 5, +):
  - `h`: kind 7, +1 (coefficient 5, not 0 or 32, so it passes the h check);
  - `z3`: kind 14, +1 (test-only, added for this test: kind 6 adds 2^20 and fails the Bz3 check);
  - `z4`: kind 5 at the bound, the coefficient set to +Bz4 (passes the ℓ∞ check).

  Each proof goes through both production verifiers, `pqz_verify` and `pqz_verify_fast`, with the trace hook on. The
  hook reports kind 2 (the seed of V4), 3 (V3) and 5 (the seed passed to `lnp_quad_many_verify`: `μ` and the final
  challenge) from `lnp-tbox.c`; the specialised verifier `pqz_sv.c` reports the same seeds as kinds 12 / 13 / 15, and
  the `verify_fast` run must see those, so a fast run that fell back to the generic code fails. The checks: kinds 2 / 3
  differ between the honest and the z3-changed proof and between the honest and the z4-changed proof, kind 5 between
  the honest and the h-changed proof, per verifier (12 checks), and the honest proof verifies. The changed proofs are
  rejected later; what matters is the seed recorded before that. A **missing record** (the verifier rejected before
  the challenge, so nothing was derived) is a FAIL, never "differ". Observation only: no proof meant to verify is built
  or searched for, and there is no cheating prover. Output lines `P6-FS …` and `VERDICT: P6-FS Fiat-Shamir binding
  (lazer#28) ok (0 failed checks of 12)`; before the fix 10 of the 12 failed (`runs/fs1-before.txt`, after:
  `runs/fs2-tbox.txt`). The Rust crate has the same test (`rust/tests/fs_bind.rs`, `fs_trace_take`; `rust/README.md`).
- **All checks together** — `check_tbox_fixes.sh`: runs both harnesses plus two more checks, and exits 1 unless
  all four fixes are in place. The third is a verifier-only fix that does not change the transcript: the z21 norm check
  ([lazer#26](https://github.com/lazer-crypto/lazer/issues/26), P6-Z21, through `sv/review/review.sh norm`). The
  fourth is the P6-FS binding test (`build/sz/fs_bind`; no verdict, or not built, is a FAIL).
  `pqz-core/research/pqzl-measure/relfix.sh` runs it.

The trace hook, the test hooks and the cheating prover are compiled only with `-DPQZ_SZ_TRACE`, `-DPQZ_TEST_HOOKS` /
`-DPQZ_L2DOM_POC`. `./build.sh native|wasm|all` defines none of them, so they do not change the library objects.

## Run

From `pqz-core/pqzl/` (the machine lock `scripts/capped` lives at the repository root):

```sh
../../scripts/capped sh -c './build.sh native && ./check_tbox_fixes.sh'
```

Success: the last line is `check_tbox_fixes: ok` and the exit code is 0 (`check_tbox_fixes: FAIL` and exit 1
otherwise). The line before it names each check: `checks: P6-SZ ok; P6-L2 ok; P6-Z21 ok; P6-FS lazer#28 ok;`.
