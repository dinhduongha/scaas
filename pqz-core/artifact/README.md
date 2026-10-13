# pqz-core reproducibility package (PQZL)

Source and scripts to rebuild pqz-core (PQZL: the LaZer fork with the five relations `R_REG`, `R_TX`, `R_BURN`,
`R_DS`, `R_DR`, the generic verifier `pqz_verify` and the specialised verifier `pqz_verify_fast`) and re-run the
measurements in `../STATUS.md`. Nothing built is published: no image, no wasm, no binaries. You build and run
everything on your own machine, and the package compares your results with `expected-results.json`.

## Status / resume (2026-10-14, WIP, machine shut down)

- **Done (source, committed):** `Dockerfile`, `Dockerfile.dockerignore`, `reproduce.sh` (quick, `--full`, `--serve`,
  `--upstream`), `results.py` (`check`, `freeze`), `web/index.html`, this README, `.gitignore` entry `artifact/out/`.
- **Tested:** `results.py freeze` on the v2 runs (`rel3/runs/v2full-*` + `sv/runs/v2-*`): 69 / 69 checks ok, and
  the table it prints matches the v2 numbers in `../STATUS.md`. `sh -n reproduce.sh`. In a plain `ubuntu:24.04`
  container (same digest), the apt snapshot `20261013T000000Z` offers exactly the pinned versions (clang-18 / lld-18
  1:18.1.3-1ubuntu1, gcc-13 / g++-13 13.3.0-6ubuntu2~24.04.1, cmake 3.28.3-1build7).
- **Untested:** the image build after the fix, and every `reproduce.sh` mode (quick, `--full`, `--serve`,
  `--upstream`), in Docker and on the host. In particular, nobody has yet checked that `--upstream` compiles
  `../xcheck/shim` (written at `b2402b5`) against the current headers, or that `http.server` serves `pqz.wasm` as
  `application/wasm`.
- **Why the first image build failed** (`runs/docker-build-1-failed.txt`): `snapshot.ubuntu.com` is HTTPS only,
  and the base image has no `ca-certificates`, so `apt-get update --snapshot` fetched nothing. Fixed in the
  `Dockerfile`: `ca-certificates` now comes from the live archive first. Not rebuilt (owner: no further runs).
- **`expected-results.json` is PROVISIONAL.** It was built from `rel3/runs/v2full-*` + `sv/runs/v2-*` (2026-10-13,
  before the z21 merge). z21 changed only the verifier, and the post-z21 `rel3/runs/final-*` gives the same
  `proofs_fnv`. Its times are pre-z21.
- **Phase 1 runs on disk:** `rel3/runs/final-*` is a complete `rel3/relfix.sh` run with the v2full sample sizes,
  post z21: rc 0, KAT 19/19, `check_tbox_fixes: ok`, `fails 0`, and `proofs_fnv` = v2 for all five relations.
  `sv/runs/final-*` was interrupted (see `final-rc.txt`). Only the portable differential is complete there: 2,710
  cases, 0 mismatches. Neither is the freeze.

Next, in order (each heavy step under the machine-wide lock):

```sh
# 1. image build + Docker tests (from the repo root); keep logs in pqz-core/artifact/runs/
scripts/capped docker build --progress=plain -t pqz-core-artifact -f pqz-core/artifact/Dockerfile pqz-core
scripts/capped docker run --rm --memory=4g -u "$(id -u):$(id -g)" -v "$PWD/pqz-core/artifact/runs/docker-quick:/out" -e OUT=/out pqz-core-artifact
scripts/capped docker run --rm --memory=4g --network none -u "$(id -u):$(id -g)" -v "$PWD/pqz-core/artifact/runs/docker-upstream:/out" -e OUT=/out pqz-core-artifact --upstream
docker run --rm -p 127.0.0.1:8000:8000 pqz-core-artifact --serve     # open http://127.0.0.1:8000/, then Ctrl-C
docker image rm pqz-core-artifact
# 2. the freeze, through the package on the host toolchain
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
docker run --rm -p 127.0.0.1:8000:8000 pqz-core-artifact --serve      # open http://127.0.0.1:8000/
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
