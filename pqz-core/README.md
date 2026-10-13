# pqz-core

The PQ Zether proof engine ([pq-zether.md](../docs/contracts/pq-zether.md) §8, CTR-PQZ-09): a fork of
[LaZer](https://github.com/lazer-crypto/lazer) at commit `3330e48` (MIT, IBM) with six layers rewritten, so the
prover and verifier run without GMP, MPFR, HEXL, floating point, `malloc`, `abort` or stdio. This is the E-S1 spike
(P6d): `R_REG` and a first `R_TX`, built natively and as freestanding `wasm32`. State, measured numbers and what is
open: [STATUS.md](STATUS.md); write-up: `docs/research/pqz-core-e-s1.md`.

## Layout

| Path | Content |
|---|---|
| `lazer/` | LaZer `3330e48` subset. The pristine copy is commit `c91b3ab`; changes are in place, marked `PQZ:`. Licence: `lazer/LICENSE` |
| `src/` | The rewritten layers and the C ABI (`pqz.h`): integers without GMP (`pqz_mpn.h`), incomplete NTT mod q = 2^42 − 215 with l = 4 (`pqz_ntt.c`), fixed-point exp for the sampler and rejection (`pqz_fixexp.h`), arena (`pqz_arena.c`), sticky error returns (`pqz_rt.h`), bitsliced software AES-256-CTR (`pqz_aes_gen.h`, from `gen_aes.py`), relations `R_REG` / `R_TX` (`pqz_rel.c`), wasm runtime (`pqz_wasm_rt.c`) |
| `params/` | LaZer codegen (`codegen/`), relation specs (`reg_params.sage`, `tx_params.sage`), generated headers `pqz_{reg,tx}_params.h`, E-S0 and E-S1 sizing (`e_s0.py`, `e_s1_proof.sage`, `estimator*.txt`; see `params/README.md`) |
| `kat/` | Arithmetic-layer KAT: `lazer_dump.c` (one source, upstream or pqz-core backend), golden `lazer-3330e48.json`, `check.py`, `build-lazer-dump.sh` |
| `test/` | `pqz_bench.c` (prove, verify, tamper checks, timings, a hash of the proofs) and `run_wasm.mjs` (the same steps under node) |
| `opt/` | P6d-2 optimisation: `bench.sh` (native + wasm bench under `scripts/capped`), `prof.sh` (gprof), `asan.sh` (ASan + UBSan, malloc path), microbenches `micro_basemul.c` / `micro_aes.c`, raw results `runs/` (STATUS.md) |
| `floor/` | Verifier-floor microbenchmarks and cost model (`docs/research/pqz-verifier-floor.md`): unit costs, prototypes, operation counts of the generic verifier; `floor/build.sh run` under `scripts/capped` |

## Build and run

```sh
./build.sh native            # build/native: libpqz.a, libpqz.so, pqz_bench, kat_dump
./build.sh wasm              # build/wasm/pqz.wasm (clang 18, wasm-ld-18, freestanding)
./build.sh all
```

Every build runs `./check_symbols.sh` on the library objects: outside themselves they may reference only `memcpy`,
`memset`, `__stack_chk_fail` (and wasm's `__stack_pointer`). The build fails on anything else (`malloc`, stdio, libm,
GMP, MPFR, `getentropy`).

```sh
build/native/pqz_bench 7 7                                  # 7 proves, 7 + 7 honest verifies per relation (JSON lines)
build/native/pqz_bench 1 0 2                                # R_TX only (3rd argument: 1 R_REG, 2 R_TX, 3 both)
opt/bench.sh <label>                                        # pqz_bench 5 5 + run_wasm.mjs 3 1 -> opt/runs/<label>-*.jsonl
node test/run_wasm.mjs 3 1                                  # the same under node
build/native/kat_dump > build/native/kat-pqz.json
python3 -I kat/check.py kat/lazer-3330e48.json build/native/kat-pqz.json   # must print 19/19
```

`R_TX` needs about 0.32 GB of arena (the bench allocates 768 MiB). Same seeds must give the same `proofs_fnv`
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

- LaZer: MIT, (c) 2022-2026 IBM, `lazer/LICENSE`; no patent grant (release gate G-LIC).
- The library objects link no GMP, MPFR, HEXL or libstdc++.
- `kat/build-lazer-dump.sh` links upstream LaZer statically with GMP / MPFR (LGPL), HEXL and libstdc++. That binary is
  a local build output, never committed or distributed (distributing it would carry LGPL relinking duties).
- Intel SDE 9.48.0 was used once, locally, to run the AVX-512 golden dump on a CPU without AVX-512. It is not
  vendored and not needed to build or test pqz-core.
