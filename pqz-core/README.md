# pqz-core

The PQ Zether proof engine ([pq-zether.md](../docs/contracts/pq-zether.md) §8, CTR-PQZ-09): a fork of
[LaZer](https://github.com/lazer-crypto/lazer) at commit `3330e48` (MIT, IBM) with six layers rewritten, so the
prover and verifier run without GMP, MPFR, HEXL, floating point, `malloc`, `abort` or stdio. This is the E-S1 spike
(P6d): `R_REG` and a first `R_TX`, built natively and as freestanding `wasm32`; then `R_BURN` (also REFRESH), `R_DS`
and `R_DR` (also the auditor), `docs/research/pqz-relations-burn-disclose.md`. State, measured numbers and what is
open: [STATUS.md](STATUS.md); write-up: `docs/research/pqz-core-e-s1.md`.

## Layout

| Path | Content |
|---|---|
| `lazer/` | LaZer `3330e48` subset. The pristine copy is commit `c91b3ab`; changes are in place, marked `PQZ:`. Licence: `lazer/LICENSE` |
| `src/` | The rewritten layers and the C ABI (`pqz.h`): integers without GMP (`pqz_mpn.h`), incomplete NTT mod q = 2^42 − 215 with l = 4 (`pqz_ntt.c`), fixed-point exp for the sampler and rejection (`pqz_fixexp.h`), arena (`pqz_arena.c`), sticky error returns (`pqz_rt.h`), bitsliced software AES-256-CTR (`pqz_aes_gen.h`, from `gen_aes.py`), relations `R_REG`, `R_TX`, `R_BURN`, `R_DS`, `R_DR` (`pqz_rel.c`), wasm runtime (`pqz_wasm_rt.c`) |
| `params/` | LaZer codegen (`codegen/`), relation specs (`{reg,tx,burn,ds,dr}_params.sage`), generated headers `pqz_*_params.h`, E-S0 and E-S1 sizing (`e_s0.py`, `e_s1_proof.sage`, `estimator*.txt`; see `params/README.md`) |
| `kat/` | Arithmetic-layer KAT: `lazer_dump.c` (one source, upstream or pqz-core backend), golden `lazer-3330e48.json`, `check.py`, `build-lazer-dump.sh` |
| `test/` | `pqz_bench.c` (prove, verify, tamper checks, timings, a hash of the proofs) and `run_wasm.mjs` (the same steps under node) |
| `opt/` | P6d-2 optimisation: `bench.sh` (native + wasm bench under `scripts/capped`), `prof.sh` (gprof), `asan.sh` (ASan + UBSan, malloc path), microbenches `micro_basemul.c` / `micro_aes.c`, raw results `runs/` (STATUS.md) |
| `rel3/` | `R_BURN` / `R_DS` / `R_DR` measurement: `bench.sh` (build, KAT, `R_REG` / `R_TX` proof hashes, timings; under `scripts/capped`), `relfix.sh` (after the owner's fix-ups: build, KAT, proof hashes, arena peak per relation, ASan + UBSan, timings of all five), raw runs `runs/` |
| `sz/`, `l2dom/` | The two LaZer `tbox` soundness fixes behind `proofSystemId` v2 ([lazer#24](https://github.com/lazer-crypto/lazer/issues/24), [#25](https://github.com/lazer-crypto/lazer/issues/25)): challenge-row trace and the pooled-slack cheating prover; `check_tbox_fixes.sh` fails if either fix is gone (`sz/README.md`), or if the z21 norm check (P6-Z21, [#26](https://github.com/lazer-crypto/lazer/issues/26), verifier only, `docs/research/pqz-z21-norm.md`) is gone |
| `glic/` | G-LIC step 1 (`docs/research/pqz-licence-inventory.md`): `absence.sh` (builds every artifact into `build/glic` and scans symbols, `DT_NEEDED`, wasm imports and strings for GMP / MPFR / HEXL; under `scripts/capped`), raw outputs and licence tables `runs/` |
| `floor/` | Verifier-floor microbenchmarks and cost model (`docs/research/pqz-verifier-floor.md`): unit costs, prototypes, operation counts of the generic verifier; `floor/build.sh run` under `scripts/capped` |
| `sv/` | P6-SV specialised verifier (`src/pqz_sv.c`, `pqz_verify_fast`; `docs/research/pqz-specialised-verifier.md`): `diff.sh` (differential test against `pqz_verify`, `test/pqz_sv_diff.c`), `bench.sh` (native portable, x86-64-v3, wasm), `fuzz.sh` (ASan + UBSan, libFuzzer `test/pqz_sv_fuzz.c`), `rel3.sh` (all five relations under one capped job: diff, bench, wasm both, ASan, KAT, both fix checks, memory per op), `check_sv_fixes.sh` (fails unless the differential test catches either tbox fix reverted in `pqz_sv.c`), raw results `runs/`; `review/` the independent review's reproducers (`review.sh dom | norm | zdiff | fuzz`: cheating provers past the final hash, the z21 differential `z21diff.c`; never compiled by `build.sh`) |

## Build and run

```sh
./build.sh native            # build/native: libpqz.a, libpqz.so, pqz_bench, kat_dump
./build.sh native-x86v3      # optional: pqz_sv.c (pqz_verify_fast) for x86-64-v3 + AES-NI, build/native-x86v3
./build.sh wasm              # build/wasm/pqz.wasm (clang 18, wasm-ld-18, freestanding)
SV=0 B=build/wasm-nosv ./build.sh wasm   # without the specialised verifier (no pqz_sv.c, no pqz_verify_fast): a
                                         #   wallet's prover build; SV=0 works for native too
./build.sh all
```

Every build runs `./check_symbols.sh` on the library objects: outside themselves they may reference only `memcpy`,
`memset`, `__stack_chk_fail` (and wasm's `__stack_pointer`). The build fails on anything else (`malloc`, stdio, libm,
GMP, MPFR, `getentropy`).

```sh
build/native/pqz_bench 7 7                                  # 7 proves, 7 + 7 honest verifies per relation (JSON lines)
build/native/pqz_bench 1 0 2                                # R_TX only (3rd argument, bit mask: 1 R_REG, 2 R_TX,
                                                            #   4 R_BURN, 8 R_DS, 16 R_DR; default 31 = all)
opt/bench.sh <label>                                        # pqz_bench 5 5 + run_wasm.mjs 3 1 -> opt/runs/<label>-*.jsonl
node test/run_wasm.mjs 3 1                                  # the same under node
PQZ_VERIFY=fast build/native/pqz_bench 2 200                # time pqz_verify_fast (wasm: PQZ_VERIFY=fast|both node ...)
build/native/pqz_sv_diff 10 5 2 1 10                        # both verifiers on honest + mutated proofs, must agree
build/native/kat_dump > build/native/kat-pqz.json
python3 -I kat/check.py kat/lazer-3330e48.json build/native/kat-pqz.json   # must print 19/19
./check_tbox_fixes.sh                                       # after ./build.sh native: the tbox fixes and the z21 check are in place
sv/review/review.sh zdiff 1                                 # z21-inflated proofs, all five relations: both verifiers agree
sv/check_sv_fixes.sh                                        # after ./build.sh native: pqz_verify_fast follows both fixes
```

`R_TX` needs about 0.30 GB of arena alone (0.31 GB after an `R_REG` in the same process: a relation's keys are built
at its first use and kept; the bench allocates 768 MiB). Same seeds must give the same `proofs_fnv`
(native and wasm) across pure implementation changes. Run the bench under `scripts/capped`.
Debug build with the libc heap instead of the arena (for ASan/LSan only): `-DPQZ_DEBUG_MALLOC`.

## Regenerate

```sh
params/codegen/run.sh <LaZer 3330e48 checkout> params/tx_params.sage > params/pqz_tx_params.h   # also reg
params/run_e_s1.sh <LaZer 3330e48 checkout> <lattice-estimator 53da598 checkout> > params/estimator-e-s1.txt
kat/build-lazer-dump.sh <work dir> v4      # upstream golden dump (v3 = AVX2 build); needs docker and network
```

All three refuse other LaZer / estimator commits and run pinned images. The codegen takes minutes; headers are
checked in and regenerated only on purpose. The v4 golden dump needs an AVX-512 CPU or Intel SDE
(`sde64 -spr -- ./lazer_dump-v4 > kat/lazer-3330e48.json`).

## Licences

- Third-party notices for a source or binary distribution: [`NOTICE`](NOTICE); inventory and gaps:
  `docs/research/pqz-licence-inventory.md`.
- LaZer: MIT, (c) 2022-2026 IBM, `lazer/LICENSE`; no patent grant (release gate G-LIC).
- The library objects link no GMP, MPFR, HEXL or libstdc++.
- `kat/build-lazer-dump.sh` links upstream LaZer statically with GMP / MPFR (LGPL), HEXL and libstdc++. That binary is
  a local build output, never committed or distributed (distributing it would carry LGPL relinking duties).
- Intel SDE 9.48.0 was used once, locally, to run the AVX-512 golden dump on a CPU without AVX-512. It is not
  vendored and not needed to build or test pqz-core.
