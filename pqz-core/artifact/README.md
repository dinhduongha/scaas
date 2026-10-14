# pqz-core reproducibility package (PQZL)

Source and scripts to rebuild pqz-core (PQZL: the LaZer fork with the five relations `R_REG`, `R_TX`, `R_BURN`,
`R_DS`, `R_DR`, the generic verifier `pqz_verify` and the specialised verifier `pqz_verify_fast`) and re-run the
measurements in `../STATUS.md`. Nothing built is published: no image, no wasm, no binaries. You build and run
everything on your own machine, and the package compares your results with `expected-results.json`.

## Status / resume (2026-10-14, WIP: Docker tests done, freeze not run)

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
| differential test | `pqz_verify` vs `pqz_verify_fast` on honest and mutated proofs, all five relations (2,710 cases, the v2-sized sample). `--full` also runs the x86-64-v3 build (1,350 cases) | portable | + x86-64-v3 |
| five relations, generic verifier | prove, verify, six tamper kinds; native `pqz_bench`, wasm32 under node | 3 proves, 3 verifies | 10 / 100 native, 5 / 30 wasm (= `rel3/relfix.sh`) |
| five relations, specialised verifier | p50 / p99 portable, x86-64-v3 + AES-NI, wasm32. In `PQZ_VERIFY=both`, every wasm verify runs both verifiers and must agree | 50 verifies | 200 (= `sv/rel3.sh`) |
| wasm prove memory | arena peak of one relation per process, prover build without SV | yes | yes |

`--full` takes the sample sizes of the frozen run, but not its ASan + UBSan build (`rel3/relfix.sh` and
`sv/rel3.sh` keep that).

## Run in Docker

The build context is `pqz-core/`. Run from the repository root:

```sh
docker build -t pqz-core-artifact -f pqz-core/artifact/Dockerfile pqz-core
mkdir -p pqz-out
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/pqz-out:/out" -e OUT=/out/quick pqz-core-artifact
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/pqz-out:/out" -e OUT=/out/full pqz-core-artifact --full
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/pqz-out:/out" -e OUT=/out/upstream pqz-core-artifact --upstream
docker run --rm --init -p 127.0.0.1:8000:8000 pqz-core-artifact --serve # open http://127.0.0.1:8000/
docker image rm pqz-core-artifact                                     # when done
```

The image is pinned: `ubuntu:24.04` by digest, apt packages from the Ubuntu snapshot archive (`APT_SNAPSHOT`), with
the measured toolchain pinned by version (clang / lld 18.1.3, gcc 13.3.0, cmake 3.28.3), node 26.8.1 by sha256, and
LaZer `3330e48` by commit (source only, for `--upstream`). The image build needs network. The runs do not; add
`--network none` if you like.

## Run on a local toolchain

You need x86-64 Linux, clang 18, `wasm-ld-18` (lld 18), node, python3 and about 1 GB of free memory.
`--upstream` also needs gcc / g++, cmake, unzip, git, `libgmp-dev` and `libmpfr-dev`.

```sh
pqz-core/artifact/reproduce.sh                 # quick
pqz-core/artifact/reproduce.sh --full
pqz-core/artifact/reproduce.sh --serve         # PORT=8000 BIND=127.0.0.1 by default
LAZER_SRC=<LaZer clone> pqz-core/artifact/reproduce.sh --upstream [N]   # without LAZER_SRC it clones from GitHub
```

Results go to `pqz-core/artifact/out/<mode>-<UTC stamp>/` (git-ignored), or to `$OUT`.

## Reading the results

`results.md` and `results.json` contain the per-relation table: proof bytes, prove p50 native / wasm, generic verify
p50, SV p50 / p99 portable / x86-64-v3 / wasm, and wasm prove peak. They also list every check against
`expected-results.json`:

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
memory is about 0.8 GB, because the bench reserves a 768 MiB arena. Wall time on the reference machine (Ryzen 5
7235HS): image build and quick run as in `runs/`; `--full` takes about the time of `rel3/relfix.sh` plus
`sv/rel3.sh` (tens of minutes). `--upstream` builds HEXL and LaZer twice, which takes several minutes.

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
- No built artifact of any kind is published with this package.

## Files

| File | Purpose |
|---|---|
| `Dockerfile`, `Dockerfile.dockerignore` | the pinned image (build context `pqz-core/`) |
| `reproduce.sh` | every mode; works in Docker and on a local toolchain |
| `results.py` | `check`: tables + comparison; `freeze`: `expected-results.json` from a frozen run |
| `expected-results.json` | reference values (PROVISIONAL until the freeze run, see Status) |
| `web/index.html` | the `--serve` page (loads the locally built `pqz.wasm`) |
| `runs/` | logs of the package's own test runs (text only) |
