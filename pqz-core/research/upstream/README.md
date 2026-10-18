# Upstream timing cross-check (P6d, 2026-10-13)

On 2026-10-13, before the optimisation in [`../opt/`](../opt/README.md), PQZL — the lattice proof system of PQZ, a C
fork of IBM's LaZer (see the parent [pqz-core README](../../README.md)) — took about 17 s to create a transfer proof and 15 s to verify it. This folder
answers one question: was that slowness caused by the fork's rewrite, or is it what LaZer itself does on the same
statement? It runs upstream LaZer `3330e48` and the `pqz-core` fork on the same `R_REG` / `R_TX` statements,
parameters, witness and seeds. The answer, method and numbers are in [RESULTS.md](RESULTS.md); summary: `docs/research/pqz-core-e-s1.md` §10.

## Contents

- `Dockerfile`: the offline upstream build image (`p6d-lazer-build:ubuntu24.04`).
- `build-upstream.sh`, `build-up-bench.sh`, `build-fork.sh`, `build-micro.sh`, `build-prof.sh`: the builds. They
  name the session scratch paths they ran from (`$S` = a LaZer clone at `3330e48` and a fork snapshot at `b2402b5`);
  set those paths to rerun.
- `shim/`: the fork's statement builder and bench compiled against upstream (`up_rel.c`, `bench.c`, `memory.h`,
  `shim.c`) and the microbenchmark (`micro.c`).
  - `up_rel.c` is the relation source at `b2402b5`, used by the scripts here.
  - `../../artifact/reproduce.sh --upstream` does not use `up_rel.c`. It compiles the current
    `../../pqzl/src/pqz_rel.c` with the same two substitutions (checked: exactly those two lines differ), so upstream
    and the fork run the same relation.
- `stub/cpuf/`: a header stub for HEXL's `cpu_features` (it reports no AVX-512, so the build needs no network fetch).
- `static/`: a portable static benchmark bundle (upstream v3 / v4-IFMA and the fork) for measuring on other
  machines; see [its own README](static/README.md).
- `runs/`: raw bench output; `prof/`: gprof flat profiles and summaries; `build-info-upstream.txt`: the upstream
  build information.

Not kept in the repository: binaries and `gmon` files (rebuild them from the scripts), the fork snapshot `fork/`, and
the build logs (`logs/`, `*.log` are git-ignored).
