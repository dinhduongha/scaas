# sz and l2dom: the LaZer tbox soundness fixes (proofSystemId v2)

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
- **All checks together** — `check_tbox_fixes.sh`: runs both harnesses plus a third check, and exits 1 unless
  all three fixes are in place. The third is a verifier-only fix that does not change the transcript: the z21 norm check
  ([lazer#26](https://github.com/lazer-crypto/lazer/issues/26), P6-Z21, through `sv/review/review.sh norm`).
  `pqz-core/research/pqzl-measure/relfix.sh` runs it.

The trace hook and the cheating prover are compiled only with `-DPQZ_SZ_TRACE` / `-DPQZ_L2DOM_POC`.
`./build.sh native|wasm|all` defines neither, so they do not change the library objects.

## Run

From `pqz-core/pqzl/` (the machine lock `scripts/capped` lives at the repository root):

```sh
../../scripts/capped sh -c './build.sh native && ./check_tbox_fixes.sh'
```

Success: the last line is `check_tbox_fixes: ok` and the exit code is 0 (`check_tbox_fixes: FAIL` and exit 1
otherwise).
