PQZ native memory-leak test (2026-10-31, result: no leak): `run.sh <corpus> <minutes> <threads> <label>` runs the repo `Harness` against a `lib/libpqz_ffi.so` in a `--memory 2g --cpus 4` container; `sample.sh` logs the container's cgroup `memory.stat` anon / file every 30 s.
`S` in `run.sh` is the session scratch dir of the run (holding `lib/`, the corpus and the samples); point it at your own dir. Build `Harness/` first (`run-tests.sh` / `harness.sh` do it).
Method, time series and verdict: `../runs/2026-10-31-leak-harness.txt`.
