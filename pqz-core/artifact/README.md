# pqz-core reproducibility package (PQZL and PQZH)

Source and scripts to rebuild both PQZ proof systems and re-run their measurements: **PQZL** (the LaZer fork, C: the six
relations `R_REG`, `R_TX`, `R_BURN`, `R_DS`, `R_DR`, `R_TX0`, the generic verifier `pqz_verify` and the specialised verifier
`pqz_verify_fast`; `../STATUS.md`), **PQZH** (Ligero, Rust: `../pqzh/ligero/`, all six forms incl. `R_TX0`, at the
proven preset; `docs/research/pqzh-ligero.md` §12–§14), the statement codec `pqz-stmt` (`../stmt/`) and **pqz-ffi**
(`../ffi/`, the one precompile over both systems). Scope: both systems (owner 2026-10-14, superseding "PQZL only" of
2026-10-13). Nothing built is published: no image, no wasm, no binaries. You build and run everything on your own
machine, and the package compares your results with `expected-results.json`.

## Status / resume (2026-10-14, branch `pqz-artifact2`: both systems; Docker quick PASS; freeze not run)

- **Done (source, commits on `pqz-artifact2`):** `Dockerfile` (build context = the repository root through the
  allowlist `Dockerfile.dockerignore`; Rust 1.97.1 by `rustup-init` sha256, `cargo fetch --locked` into the image,
  apt retries, `CARGO_BUILD_JOBS=2` / `RUST_TEST_THREADS=2`), `reproduce.sh` (PQZH, `pqz-stmt`, pqz-ffi and vector
  stages in quick and `--full`; `--serve` builds both wasm modules), `results.py` (PQZH, pqz-ffi and vector checks,
  three tables; `freeze` takes the Ligero and pqz-ffi run prefixes), `expected-results.json` (PROVISIONAL, below),
  `web/index.html` (PQZH prove / verify of any form next to PQZL `R_TX`), this README.
- **Provisional expected results:** `results.py freeze` from `../rel3/runs/tx0c` + `../sv/runs/tx0c` (PQZL, unchanged:
  regenerated 2026-10-15 with `R_TX0`; the other five relations byte-identical to the previous file), `../pqzh/ligero/runs/l15-tx0-proven` (PQZH, `d58e20a`,
  1,000 verifies native and wasm32) and `../ffi/runs/ffi1f2` (pqz-ffi): `runs/art2-provisional-freeze.md`.
- **Docker tests (2026-10-14/15, AMD Ryzen 5 7235HS, no avx512ifma; logs in `runs/art2-*`):**
  - Image: `runs/art2-docker-build-6.txt`, pinned snapshot `20261013T000000Z` (its apt layer is the one built in
    `runs/art2-docker-build-4.txt`: 42 min, because snapshot.ubuntu.com kept answering 500 / 502 / 503; builds 1 and
    2, `runs/art2-docker-build-{1,2}-failed-snapshot-502.txt`, failed on that before `Acquire::Retries` was added).
    Same pinned toolchain as before plus rustc / cargo 1.97.1; image 1.92 GB (was 1.08 GB; the Rust layer is
    762 MB); accepted (controller 2026-10-15): the image is built locally and never pushed. Build 3, `runs/art2-docker-build-3-probe-live-archive.txt`, was a probe only: the live archive with
    the same pinned versions (`runs/art2-live-archive-versions.txt`), not cited.
  - Quick mode `runs/art2-docker-quick/` (`summary.txt`, `results.md`), `docker run --network none --memory=4g
    --memory-swap=4g -u`: **RESULT PASS, 148 ok / 0 FAIL / 0 warn**, 27 min. PQZL as before (every `proofs_fnv`,
    KAT 19/19, both fix checks, differential 2,972 cases 0 mismatches). PQZH: 13 + 17 tests (6 × 960 mutations, 0
    accepted / 0 panics), `--no-default-features` tests and clippy float lint, xcheck 12 / 12 equal + `kat_stmt: ok`,
    `pqz-stmt` xcheck, every proof hash and length of seeds 0, 1 native and seed 1 wasm32 equal to `l15-tx0`, native
    = wasm32, every `max_len_exact` equal, wasm32 ≤ 48.1 MiB. pqz-ffi: self-test `ed910a2c…`, 443 rejection cases,
    differential 0 disagreements, symbols ok, C smoke test ok, 17 digest lines native = wasm32 = `ffi1f2`. Vectors:
    `pqz-vectors --check: 15 files, 11371429 B: ok`, `pqz_kat: ok`, wasm32 replay 34 / 34 byte-equal and valid.
  - A first quick run on the probe image, `runs/art2-docker-quick-1-probe-live-archive-failed-symbols-path/`, passed
    at the time but showed a false pass: `../check_symbols.sh` got a relative archive path, `llvm-nm` said "No such
    file", and the script still printed `symbols ok` (its `nm` errors are lost in a pipe). `reproduce.sh` now passes
    an absolute path, and `results.py` fails `ffi-native.txt` on "No such file" (re-checked: that run now FAILs).
  - `--serve` `runs/art2-docker-serve.txt`: `/` 200 `text/html` (the PQZL / PQZH page), `pqz.wasm` 200
    `application/wasm` (411,510 B) and `pqzh_ligero_wasm.wasm` 200 `application/wasm` (276,022 B), both with the wasm
    magic; `docker stop` 0.23 s with `--init`. The page's JavaScript was not exercised in a browser (only the HTTP
    side). Two earlier attempts (`runs/art2-docker-serve-{1,2}-*.txt`) curled before the server had bound (docker's
    port proxy resets the connection), which `curl --retry-all-errors` fixed.
  - `docker image rm pqz-core-artifact` done; no image kept or pushed.
- **Not tested:** `--full` in Docker (as before: the freeze runs on the host toolchain), `--upstream` after this
  change (the Dockerfile kept every LaZer / GMP / HEXL pin; only `cmake --build -j2` changed).

**Pending for the freeze (after P6e gates A / B):**

1. One `--full` run, the frozen numbers from it, on the host toolchain under the machine lock (both systems,
   pqz-ffi, the vectors incl. `tamper.py`):

   ```sh
   OUT=pqz-core/artifact/runs/freeze-<date> scripts/capped pqz-core/artifact/reproduce.sh --full
   cd pqz-core && python3 -I artifact/results.py freeze "frozen <date>" artifact/runs/freeze-<date> \
     > artifact/expected-results.json      # prints the three tables (Markdown) on stderr
   ```
2. Write the frozen tables and the reference machine into `../STATUS.md` and `../README.md`; remove the
   PROVISIONAL notes here.
3. ~~PQZL `R_TX0` outside the package's PQZL runs~~ Done 2026-10-15 (controller): `pqz_bench` / `run_wasm.mjs`
   mask 63, the `R_TX0` per-process run, `results.py` `RELS` with `R_TX0`, and the differential sample of
   `sv/rel3.sh` (9 arguments, `n_tx0` = 12: 3,484 cases). The Docker quick run above predates it (five PQZL
   relations, 2,972 differential cases: the 8-argument sample gave `R_TX0` the default 4); the host quick run below
   has it.

**Host quick run with `R_TX0` (2026-10-15)** `runs/art2-host-quick/` (`summary.txt`), the host toolchain under
`scripts/capped` (no Docker: P6f needed it): **RESULT PASS, 159 ok / 0 FAIL / 0 warn**, 30 min. PQZL six relations:
every `R_TX0` `proofs_fnv` equal to `tx0c` (n = 1, 2, 3; native, x86-64-v3, wasm, wasm `both`, wasm without SV), its
largest proof 42,432 B (`tx0c` 42,441 B, 0.02 %), its wasm prove peak equal to the byte; differential 3,484 cases, 0
mismatches. PQZH, pqz-ffi and the vectors as in the Docker run. Same commit: `../check_symbols.sh` fails on a missing
file or an `nm` error (`../STATUS.md` Open 9, closed; `runs/art2-check-symbols.txt`: `./build.sh native` and
`test/check_symbols_neg.sh` ok; `../glic/runs/absence-2026-10-15.txt`: the three real-file scans and the G-LIC
absence check pass).

Earlier freeze notes (PQZL only, kept for the record) are in the section below.

### Earlier status (PQZL only, 2026-10-14, before the scope change)

- **Done (source, committed):** `Dockerfile`, `Dockerfile.dockerignore`, `reproduce.sh` (quick, `--full`, `--serve`,
  `--upstream`), `results.py` (`check`, `freeze`), `web/index.html`, this README, `.gitignore` entry `artifact/out/`.
- **Tested before the Docker runs:** `results.py freeze` on the v2 runs (`rel3/runs/v2full-*` + `sv/runs/v2-*`):
  69 / 69 checks ok, and the table it prints matches the v2 numbers in `../STATUS.md`. `sh -n reproduce.sh`.
- **Docker tests (2026-10-14, AMD Ryzen 5 7235HS, no avx512ifma; logs and outputs in `runs/`):**
  - Image build `runs/docker-build-2.txt`: ok, no Dockerfile change after the `ca-certificates` fix (first failure:
    `runs/docker-build-1-failed.txt`, `snapshot.ubuntu.com` is HTTPS only). The log shows the pinned versions
    installed: clang-18 / lld-18 1:18.1.3-1ubuntu1, gcc-13 / g++-13 13.3.0-6ubuntu2~24.04.1, cmake 3.28.3-1build7;
    node 26.8.1 sha256 ok; LaZer `3330e48`. Image 1.08 GB. `runs/docker-build-3.txt` and `-4.txt` are the rebuilds
    after the shim and `reproduce.sh` changes below (only the `COPY` layer changed).
  - Quick mode `runs/docker-quick/` (`summary.txt`): RESULT PASS, 66 ok / 0 FAIL against the provisional
    `expected-results.json`. Every `proofs_fnv` equal (5 relations x 7 run files, native, x86-64-v3, wasm, wasm
    `both`, wasm without SV); proof sizes and wasm prove peaks equal to the byte (only `R_REG` max 28,085 vs 28,108,
    within 0.5 %); KAT 19/19, `check_tbox_fixes: ok`, `check_sv_fixes: ok`, differential 2,710 cases 0 mismatches.
    About 15 min.
  - `--upstream --network none` `runs/docker-upstream/` (image `runs/docker-build-4.txt`): ok, upstream and the fork
    on the same relation. The upstream bench now compiles the fork's own `../src/pqz_rel.c` (not a copy), with the
    two upstream-API substitutions of the original cross-check (no bounded decoder, no coder `err` flag);
    `runs/docker-upstream/upstream-relation.txt` is the check: exactly those two lines differ, and `reproduce.sh`
    stops otherwise. Both sides prove and verify the same statement and witness (`../xcheck/shim/bench.c`). Proofs
    do not cross-verify, by design: the fork's tbox fixes P6-SZ / P6-L2 change the transcript (`proofSystemId` v2).
    Upstream v3 and v4 (IFMA) build; KAT upstream v3 19/19; v4 is built only (no avx512ifma on this CPU, so the v4
    KAT and bench are skipped, as designed). Bench N=3 medians, fails 0 on both sides:

    | binary | `R_REG` prove | `R_REG` verify | `R_TX` prove | `R_TX` verify | `R_REG` / `R_TX` bytes |
    |---|---|---|---|---|---|
    | upstream `3330e48` x86-64-v3 | 548 ms | 513 ms | 6,581 ms | 6,403 ms | 28,106 / 42,756 |
    | fork (portable build) | 247 ms | 178 ms | 1,012 ms | 613 ms | 28,086 / 42,771 |

    Relation differences `b2402b5` -> now (`git diff b2402b5..HEAD -- src/pqz_rel.c`; `params/pqz_reg_params.h` and
    `pqz_tx_params.h` unchanged): the `R_TX` statement layout (640 B header, fee a be32 word at 256 that must be
    < 2^64, was a be8 after the body); `build_tx` / `tx_witness` became `build_debit` / `debit_witness` (shared with
    `R_BURN`; `LAY_TX` = the old slot bases, same rows, same selectors); relation keys built at first use; `A` global;
    `#ifdef` code not compiled here (l2dom PoC, SV, test hooks); the new relations. No `R_REG` / `R_TX` equation
    changed. Earlier runs, kept: `runs/docker-upstream-1-failed/` (the shim bench built the `b2402b5` statement
    layout, fork `R_TX` prove rc 3) and `runs/docker-upstream-2-oldrel/` (after the layout fix in
    `../xcheck/shim/bench.c` and `up_rel.c`, upstream still on the `b2402b5` relation copy: every median within
    10 % of the table above, run-to-run noise at N=3). `../xcheck/shim/up_rel.c` stays the `b2402b5` copy for the
    older `../xcheck/` scripts.
  - `--serve` `runs/docker-serve-*.txt`: `/` 200 `text/html`, `pqz.wasm` 200 `Content-type: application/wasm`
    (405,882 B, wasm magic). No change needed: Python 3.12 maps `.wasm` itself. Without `--init`, `docker stop` ended
    it with 137 after the grace period (`http.server` as PID 1 ignores SIGTERM); the `--serve` command lines here and
    in the `Dockerfile` now use `docker run --init`, and `docker stop` takes 0.2 s (`runs/docker-serve-init.txt`).
  - `docker image rm pqz-core-artifact` done; no image kept or pushed.
- **Not tested:** `--full` in Docker (controller decision 2026-10-14: no Docker `--full` run; the freeze stays on the
  host toolchain), and every mode on the host toolchain (the freeze below is the first host run).
- **`expected-results.json` is PROVISIONAL.** It was built from `rel3/runs/v2full-*` + `sv/runs/v2-*` (2026-10-13,
  before the z21 merge). z21 changed only the verifier, and the post-z21 `rel3/runs/final-*` gives the same
  `proofs_fnv`, as does the Docker quick run above. Its times are pre-z21.
- **Phase 1 runs on disk:** `rel3/runs/final-*` is a complete `rel3/relfix.sh` run with the v2full sample sizes,
  post z21: rc 0, KAT 19/19, `check_tbox_fixes: ok`, `fails 0`, and `proofs_fnv` = v2 for all five relations.
  `sv/runs/final-*` was interrupted (see `final-rc.txt`). Only the portable differential is complete there: 2,710
  cases, 0 mismatches. Neither is the freeze.

**Freeze postponed (controller 2026-10-14):** a first `--full` run was stopped after the KAT, fix checks and part of the differential test (`runs/freeze-2026-10-14-interrupted-console.txt`), because P6e found that the PQZL prover's masks are not hedged as CTR-PQZ-19 requires (P6e plan gap G2, Task 1). The fix changes every honest proof (`proofs_fnv`), so the freeze runs after P6e gate A (PQZL vectors and `proofSystemId` frozen), with a new date in the paths below.

**Provisional expected results after P6e Task 1 (2026-10-14, branch `p6e-a1`):** `expected-results.json` is regenerated with `results.py freeze` from the hedged-prover runs `../rel3/runs/hedge2-*` and `../sv/runs/hedge2-*` (69 / 69 checks ok, `runs/hedge2-provisional-freeze.md`; the first hedge run without the inner witness tag, `runs/hedge-provisional-freeze.md`, is superseded): new `proofs_fnv` for every relation and n, proof sizes within noise (largest proof ±30 B), arena and wasm prove peaks identical. Still provisional; the freeze after gate A replaces it. The Docker runs in `runs/docker-*` predate it (v2 hashes).

**Provisional expected results after P6e Task 2 (2026-10-14, branch `p6e-a2`):** regenerated with `results.py freeze` from `../rel3/runs/tx0-*` and `../sv/runs/tx0-*` (69 / 69 checks ok, `runs/tx0-provisional-freeze.md`). Only `R_TX` changes: its bench statement now carries `auditorOn = 1` in the header word at 448 (P6e ruling R6: the 83,072-byte form requires it; the word was filler before), so its proofs and every `R_TX` `proofs_fnv` change; `R_REG`, `R_BURN`, `R_DS`, `R_DR` are byte-identical to `hedge2`. Then regenerated again from `../rel3/runs/tx0b-*` / `../sv/runs/tx0b-*` (69 / 69, `runs/tx0b-provisional-freeze.md`): the `R_TX` and `R_BURN` bench statements carry the canonical salt word (16 zero bytes ‖ salt), so their hashes change once more; `R_REG`, `R_DS`, `R_DR` unchanged. And from `../rel3/runs/tx0c-*` / `../sv/runs/tx0c-*` (69 / 69, `runs/tx0c-provisional-freeze.md`): the D15 zero words in the bench headers (`R_TX` recipient, `R_BURN` toUA / auditorOn) change `R_TX` and `R_BURN` once more. The new relation `R_TX0` (transfer without the auditor) is not in this package's runs yet (`reproduce.sh` passes the relation mask 31; `results.py` skips relations it does not list).

Next (heavy step under the machine-wide lock): the freeze, through the package on the host toolchain.

```sh
OUT=pqz-core/artifact/runs/freeze-2026-10-14 scripts/capped pqz-core/artifact/reproduce.sh --full
cd pqz-core && python3 -I artifact/results.py freeze "frozen 2026-10-14 (post z21)" artifact/runs/freeze-2026-10-14 \
  > artifact/expected-results.json      # prints the frozen table (Markdown) on stderr
```

After the freeze, write the frozen table and the reference machine into `../STATUS.md` and the five-relation table
of `../README.md`. Compare it with `rel3/runs/final-*` (a direct relfix run). Then remove the PROVISIONAL notes.

## What is reproduced

| Step | What it shows | quick | `--full` |
|---|---|---|---|
| build | `./build.sh all`, `native-x86v3`, wasm without SV (`SV=0`); the symbol scan rejects any libc / GMP / MPFR reference in the library objects | yes | yes |
| KAT | arithmetic layer = upstream LaZer `3330e48`, 19/19 cases (`kat/lazer-3330e48.json`) | yes | yes |
| `check_tbox_fixes.sh` | the three LaZer `tbox` fixes are in place: P6-SZ, P6-L2 (`proofSystemId` v2), and the verifier-only z21 norm check (P6-Z21). Each has a cheating-prover PoC and a control run | yes | yes |
| `sv/check_sv_fixes.sh` | `pqz_verify_fast` follows both transcript fixes. With either fix reverted, the differential test must fail | yes | yes |
| differential test | `pqz_verify` vs `pqz_verify_fast` on honest and mutated proofs, all six relations (3,484 cases, the sample of `sv/rel3.sh`). `--full` also runs the x86-64-v3 build (1,350 cases) | portable | + x86-64-v3 |
| six relations, generic verifier | prove, verify, six tamper kinds; native `pqz_bench`, wasm32 under node | 3 proves, 3 verifies | 10 / 100 native, 5 / 30 wasm (= `rel3/relfix.sh`) |
| six relations, specialised verifier | p50 / p99 portable, x86-64-v3 + AES-NI, wasm32. In `PQZ_VERIFY=both`, every wasm verify runs both verifiers and must agree | 50 verifies | 200 (= `sv/rel3.sh`) |
| wasm prove memory | arena peak of one relation per process, prover build without SV | yes | yes |

**PQZH (Ligero, Rust 1.97.1)**, at THE proven preset (`Params::preset`, `--regime proven --r431 1`), all six forms
(`R_REG`, `R_TX`, `R_BURN`, `R_DS`, `R_DR`, `R_TX0`):

| Step | What it shows | quick | `--full` |
|---|---|---|---|
| `cargo test` (`pqzh/ligero`) | 13 unit + 17 integration tests: 6 × 960 mutated inputs rejected, every negative witness, cross-form, hedged proofs, the EVM fixtures | yes | yes |
| production build | `--no-default-features`: tests, examples / bins, `cargo clippy -- -D clippy::float_arithmetic` | yes | yes |
| C ↔ Rust cross-check | `../pqzh/xcheck/ligero.sh`: statement and witness bytes of the Rust client = `pqz_bench.c`'s (12 files), then `kat_stmt.py` (each statement parses under `pqz_kat.py` with PQZH's id only and is rebuilt byte for byte) | yes | yes |
| `pqz-stmt` | `../stmt/xcheck.sh`: unit tests (release and debug), C and `pqz_kat.py` cross-check, wasm32 build | yes | yes |
| native bench | `ligero_bench`: proof bytes, `max_len_exact`, prove, prove heap peak, verify p50 / p99, 12 mutation kinds, FNV of the proofs of seeds 0..n-1 | 2 proofs, 20 verifies, 12 × 2 mutations | 5, 1,000, 12 × 80 (= `pqzh/ligero/runs/tx0.sh`) |
| wasm32 bench | `run_wasm.mjs` under node: the same, linear memory ≤ 256 MiB, FNV of seed 1 (= native) | 2 proofs, 20 verifies, 12 × 1 | 2, 1,000, 12 × 4 (the gate-B method) |

**pqz-ffi** (`../ffi/`, the one precompile over both systems): `cargo test --features prove,test-hooks` (self-test
hash, every decoder rejection, the PQZL differential test, node faults, the verify-only process, fill determinism, and
the native digest lines); `cargo test --lib` without `prove`; the verify-only cdylib, its symbol scan
(`../check_symbols.sh`), no test hooks in it, the C smoke test against `pqz_ffi.h`; clippy
`-D clippy::float_arithmetic`; the wasm32 builds and digest lines (must equal native); `ffi_bench` (20 quick, 200
`--full`). This is `ffi/run.sh` minus its `cargo +stable clippy` (the image has 1.97.1's clippy) and `/usr/bin/time`.

**Vectors** (`smartcontracts/vectors/pqz/`, P6e Task 11; the generator is pqz-ffi's `pqz-vectors`): `pqz-vectors
--check` (a second generation compared byte for byte; every honest proof and negative input through `pqz_precompile`,
PQZL also through the generic verifier), `pqz_kat.py --check` (the independent Python checker) and the wasm32 replay
(`ffi/vectors/replay_wasm.mjs`: every proof proved again in wasm32, byte-equal and valid), quick and `--full`;
`tamper.py` (single-leaf edits, each must be caught) with `--full` only. As `ffi/vectors/run.sh` in check mode: the
package never rewrites the vectors.

`--full` takes the sample sizes of the frozen runs, but not PQZL's ASan + UBSan build (`rel3/relfix.sh` and
`sv/rel3.sh` keep that).

## Run in Docker

The build context is the repository root, narrowed by `Dockerfile.dockerignore` to `pqz-core/`,
`smartcontracts/vectors/pqz/` (the vectors and `pqz_kat.py`: read by the vector checks, the PQZH and `pqz-stmt`
cross-checks, and pqz-ffi's `build.rs` for the self-test proofs) and
`smartcontracts/evm/test/vectors/pqzh-ligero/` (the Ligero crate's EVM fixture test), about 12 MB. Run from the
repository root:

```sh
docker build -t pqz-core-artifact -f pqz-core/artifact/Dockerfile .   # needs network; cargo / cc capped at 2 jobs
mkdir -p pqz-out
docker run --rm --memory=4g --memory-swap=4g --network none -u "$(id -u):$(id -g)" -v "$PWD/pqz-out:/out" -e OUT=/out/quick pqz-core-artifact
docker run --rm --memory=4g --memory-swap=4g --network none -u "$(id -u):$(id -g)" -v "$PWD/pqz-out:/out" -e OUT=/out/full pqz-core-artifact --full
docker run --rm --memory=4g --memory-swap=4g -u "$(id -u):$(id -g)" -v "$PWD/pqz-out:/out" -e OUT=/out/upstream pqz-core-artifact --upstream
docker run --rm --memory=4g --memory-swap=4g --init -p 127.0.0.1:8000:8000 pqz-core-artifact --serve # open http://127.0.0.1:8000/
docker image rm pqz-core-artifact                                     # when done
```

The image is pinned: `ubuntu:24.04` by digest, apt packages from the Ubuntu snapshot archive (`APT_SNAPSHOT`), with
the measured toolchain pinned by version (clang / lld 18.1.3, gcc 13.3.0, cmake 3.28.3), node 26.8.1 by sha256,
LaZer `3330e48` by commit (source only, for `--upstream`), `rustup-init` 1.29.1 by sha256 and Rust 1.97.1 (minimal
profile + `wasm32-unknown-unknown` + clippy; rustup checks every component against the 1.97.1 channel manifest's
sha256), and the crates by their committed `Cargo.lock` (`cargo fetch --locked` into the image for `pqzh/ligero`,
`pqzh/ligero/wasm`, `stmt`, `ffi`, `ffi/wasm`). The image build needs network. The runs
do not (every cargo call is `--locked --offline`); `--network none` above. `--upstream` clones nothing either,
since LaZer is in the image.

## Run on a local toolchain

You need x86-64 Linux, clang 18, `wasm-ld-18` (lld 18), node, python3, rustup with Rust 1.97.1
(`../pqzh/rust-toolchain.toml` and `../ffi/rust-toolchain.toml` select it; `wasm32-unknown-unknown` and clippy
installed), the crates in the cargo cache (`cargo fetch --locked` once in each crate directory: the runs are offline),
binutils (`strings`) and about 1 GB of free memory.
`--upstream` also needs gcc / g++, cmake, unzip, git, `libgmp-dev` and `libmpfr-dev`.

```sh
pqz-core/artifact/reproduce.sh                 # quick
pqz-core/artifact/reproduce.sh --full
pqz-core/artifact/reproduce.sh --serve         # PORT=8000 BIND=127.0.0.1 by default
LAZER_SRC=<LaZer clone> pqz-core/artifact/reproduce.sh --upstream [N]   # without LAZER_SRC it clones from GitHub
```

Results go to `pqz-core/artifact/out/<mode>-<UTC stamp>/` (git-ignored), or to `$OUT`.

## Reading the results

`results.md` and `results.json` contain three tables. PQZL per relation: proof bytes, prove p50 native / wasm, generic
verify p50, SV p50 / p99 portable / x86-64-v3 / wasm, and wasm prove peak. PQZH per form: proof bytes (max),
`max_len_exact`, prove p50 native / wasm32, verify p50 / p99 native and wasm32, prove memory (native heap peak, wasm32
linear memory) and the number of verifies. pqz-ffi: the self-test hash and, per system and form, verify p50 / p99
through the C ABI. They also list every check against `expected-results.json`.

PQZH and pqz-ffi checks:

- **exact:** the FNV-1a hash and the length of each PQZH proof, keyed by its seed (native seeds 0..n-1, wasm32 seed
  1), and native = wasm32 for the same seed; `max_len_exact` per form, every proof ≤ `max_len_exact` = the
  verifier's bound; wasm32 linear memory ≤ 256 MiB; every bench `fails 0` (0 mutations accepted, 0 panics) with all
  six forms; the text stages end with `rc=0` and show their markers (`kat_stmt: ok`, `xcheck: C 6 / 6 forms equal`,
  `0 verifier panics caught`, `c_abi: ok (0 failures)`, `symbols ok`, test hooks 0, `0 disagreements`); the pqz-ffi
  self-test hash and digest lines equal the frozen ones, and the wasm32 digest lines equal native; the vectors:
  `pqz-vectors --check: … ok` (no `DIFF` / `EXTRA`), `pqz_kat: ok`, every wasm32 replay row byte-equal and valid,
  `tamper: … caught: ok`.
- **within a tolerance:** wasm32 / native prove and verify (±50 %, warn only).
- **informational:** times and memory.

PQZL checks:

- **exact:** `proofs_fnv` (an FNV-1a hash over the proofs of seeds 0..n-1, keyed by n). Native, x86-64-v3 and wasm
  must give the same hash, because the proofs are byte-identical across builds. The KAT must give 19/19. Both fix
  checks must print `ok`. The differential test must report 0 mismatches. Every bench must report `fails 0`.
- **within a tolerance** (stated in `expected-results.json`): largest proof size ±0.5 %, wasm prove arena peak ±1 %.
  Two ratios get ±50 % and only warn, because they depend on the machine: SV speed-up (generic p50 / SV p50,
  native) and wasm / native prove.
- **informational:** all times. Expect them to differ on other CPUs. The reference numbers were measured on the
  machine in `expected-results.json` (`machine`).

`reproduce.sh` exits 0 only when no check fails (`RESULT: PASS`).

**Hardware and time.** The package targets x86-64. Without AVX2 + AES-NI the x86-64-v3 runs are skipped. Peak
memory is about 0.8 GB, because the PQZL bench reserves a 768 MiB arena (pqz-ffi's wasm32 digest run about 0.6 GB);
the documented `docker run --memory=4g` leaves headroom. Wall time on the reference machine (Ryzen 5 7235HS): image
build a few minutes plus the apt snapshot download (which took 42 min while snapshot.ubuntu.com was failing); quick
27 min (PQZL 18, PQZH 4, pqz-ffi 4, vectors 2); `--full` takes about the time of `rel3/relfix.sh` plus `sv/rel3.sh`
(tens of minutes) plus PQZH's 1,000-verify benches and `tamper.py`. `--upstream` builds HEXL and LaZer twice, which
takes several minutes.

## `--upstream`: upstream LaZer and AVX-512

`--upstream` builds upstream LaZer `3330e48` from source in two variants: x86-64-v3 (AVX2) and x86-64-v4 with
AVX-512 IFMA / VBMI2. Each variant includes HEXL from LaZer's `third_party` zip, links the distribution's GMP /
MPFR, and uses the flags of `../xcheck/static/build.sh`. Then it does three things:

1. It checks the upstream KAT dump against the golden `kat/lazer-3330e48.json`.
2. It runs the `R_REG` / `R_TX` cross-check bench through `../xcheck/shim`. This compares upstream and the fork on
   the same statements, parameters and seeds (`../xcheck/README.md`).
3. It runs the fork's bench (`bench_fork`).

**Building without AVX-512.** Building needs only the compiler flags (`-march=x86-64-v4 -mavx512ifma
-mavx512vbmi2`), because gcc emits AVX-512 code on any host. HEXL's configure test normally compiles *and runs*
its AVX-512 probe, so here it is relaxed to "compiles". **Running needs the CPU:** an AVX-512 IFMA CPU (Ice Lake /
Sapphire Rapids, Zen 4 or later) or Intel SDE (`sde64 -spr -- ...`). `reproduce.sh` runs the v4 binaries only
when `/proc/cpuinfo` lists `avx512ifma`. Otherwise it prints that they were skipped and why. At run time, HEXL picks
its kernels from CPUID (`../xcheck/static/cpuf`), so `HEXL_DISABLE_AVX512IFMA=1` gives an A/B on the same binary.

## Licences

- pqz-core includes a modified LaZer subset: MIT, (c) IBM, `../lazer/LICENSE`. Third-party notices are in
  `../NOTICE`.
- The pqz-core library links no GMP, MPFR or HEXL.
- `--upstream` builds upstream LaZer with HEXL (Apache-2.0) and links GMP / MPFR (LGPL-3.0+). It does this only
  inside the container, or on your machine, from source. The binaries stay in `build/upstream/` (git-ignored).
  This package never ships them, and you should not distribute them: distributing a binary with GMP / MPFR linked in
  carries LGPL relinking duties.
- PQZH and pqz-ffi use the crates in their `Cargo.lock` (`sha3` and its RustCrypto dependencies, MIT / Apache-2.0),
  fetched from crates.io when you build the image.
- No built artifact of any kind is published with this package.

## Files

| File | Purpose |
|---|---|
| `Dockerfile`, `Dockerfile.dockerignore` | the pinned image (build context `pqz-core/`) |
| `reproduce.sh` | every mode; works in Docker and on a local toolchain |
| `results.py` | `check`: tables + comparison; `freeze`: `expected-results.json` from a frozen run (both systems + pqz-ffi) |
| `expected-results.json` | reference values (PROVISIONAL until the freeze run, see Status) |
| `web/index.html` | the `--serve` page (loads the locally built `pqz.wasm` and `pqzh_ligero_wasm.wasm`) |
| `runs/` | logs of the package's own test runs (text only) |
