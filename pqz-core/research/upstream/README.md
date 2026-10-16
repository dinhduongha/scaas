# Upstream timing cross-check (P6d, 2026-10-13)

Upstream LaZer `3330e48` against the `pqz-core` fork on the same `R_REG` / `R_TX` statements, parameters, witness
and seeds. Results and method: `RESULTS.md`; summary: `docs/research/pqz-core-e-s1.md` §10.

- `Dockerfile`: the offline upstream build image (`p6d-lazer-build:ubuntu24.04`).
- `build-upstream.sh`, `build-up-bench.sh`, `build-fork.sh`, `build-micro.sh`, `build-prof.sh`: the builds. They
  name the session scratch paths they ran from (`$S` = a LaZer clone at `3330e48` and a fork snapshot at `b2402b5`);
  set those paths to rerun.
- `shim/`: the fork's statement builder and bench compiled against upstream (`up_rel.c`, `bench.c`, `memory.h`,
  `shim.c`) and the microbenchmark (`micro.c`). `up_rel.c` is the `b2402b5` relation source, used by the scripts
  here. `../artifact/reproduce.sh --upstream` does not use it: it compiles the current `../src/pqz_rel.c` with the
  same two substitutions (checked: exactly those two lines differ), so upstream and the fork run the same relation.
- `stub/cpuf/`: header stub for HEXL's `cpu_features` (reports no AVX-512; no network fetch).
- `static/`: a portable static benchmark bundle (upstream v3 / v4-IFMA and the fork) for measuring on other
  machines; its own README.
- `runs/`: raw bench output; `prof/`: gprof flat profiles and summaries; `logs/`: build logs.

Binaries and `gmon` files are not kept (rebuild from the scripts).
