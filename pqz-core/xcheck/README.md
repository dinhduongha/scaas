# Upstream timing cross-check (P6d, 2026-10-13)

Upstream LaZer `3330e48` against the `pqz-core` fork on the same `R_REG` / `R_TX` statements, parameters, witness
and seeds. Results and method: `RESULTS.md`; summary: `docs/research/pqz-core-e-s1.md` §10.

- `Dockerfile`: the offline upstream build image (`p6d-lazer-build:ubuntu24.04`).
- `build-upstream.sh`, `build-up-bench.sh`, `build-fork.sh`, `build-micro.sh`, `build-prof.sh`: the builds. They
  name the session scratch paths they ran from (`$S` = a LaZer clone at `3330e48` and a fork snapshot at `b2402b5`);
  set those paths to rerun.
- `shim/`: the fork's statement builder and bench compiled against upstream (`up_rel.c`, `bench.c`, `memory.h`,
  `shim.c`) and the microbenchmark (`micro.c`).
- `stub/cpuf/`: header stub for HEXL's `cpu_features` (reports no AVX-512; no network fetch).
- `runs/`: raw bench output; `prof/`: gprof flat profiles and summaries; `logs/`: build logs.

Binaries and `gmon` files are not kept (rebuild from the scripts).
