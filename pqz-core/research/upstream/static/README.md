# pqz-bench: static benchmark bundle, upstream LaZer vs the pqz-core fork

This folder builds a portable version of the upstream timing cross-check ([`../RESULTS.md`](../RESULTS.md)), which
compared IBM's LaZer library with PQZL, our fork of it (parent [pqz-core README](../../../README.md)). The build makes
fully static x86-64 binaries packed in one tarball, so the owner can copy it to another machine — one with AVX-512
IFMA, or the chain host — and measure there without installing anything. The statement, params headers, witness and
seeds are the same as in the cross-check. Each binary runs `R_REG` and `R_TX` prove and verify.

In this folder: `build.sh` (builds the bundle), `run.sh` (runs it; shipped inside the bundle) and `cpuf/` (the CPU
feature probe described below). The reference run at the end (bundle `pqz-bench-fd8600f`, 2026-10-13) measured the fork
before its optimisation in [`../../opt/`](../../opt/README.md).

**The four binaries**

| binary | what |
|---|---|
| `bench_up_v3` | upstream LaZer `3330e48` through `../shim/`, gcc 13 `-O3 -march=x86-64-v3 -maes -mpclmul`. HEXL takes its AVX2 / scalar path. Runs on any x86-64-v3 CPU (Haswell / Zen 1 or later). |
| `bench_up_v4` | upstream, `-O3 -march=x86-64-v4 -mavx512ifma -mavx512vbmi2 -maes -mpclmul`, with HEXL's AVX-512 kernels (DQ, IFMA, VBMI2) compiled in. Needs an AVX-512 IFMA CPU (Ice Lake / Sapphire Rapids, Zen 4 or later). `run.sh` skips it elsewhere. |
| `bench_fork` | the fork as shipped: `pqz-core/pqzl/build.sh native` (clang 18 `-O2`, generic x86-64, `PQZ_ASSERT=1`). |
| `bench_fork_v3` | the fork with `-O3 -march=x86-64-v3 -DPQZ_ASSERT=0`. A compiler-flag comparison only, not a shipped build. |

All four are `statically linked` (glibc, GMP, MPFR, libstdc++), single-threaded and not stripped.
`build-info.txt` in the bundle lists the compilers, library versions, HEXL configure result and sha256 of each binary.

## How v4 picks the IFMA kernels

HEXL dispatches at run time (`hexl/util/cpu-features.hpp`): it reads the `avx512f/dq/vl/ifma/vbmi2` flags from
google/cpu_features and calls an AVX-512 kernel only when the CPU has the flag. The 52-bit IFMA NTT and
element-wise kernels also need modulus < 2^50 or 2^51, and LaZer's 50-bit CRT moduli meet that. Normally HEXL's
cmake fetches cpu_features from GitHub. The cross-check replaced it with a stub that reports no AVX-512
(`../stub/cpuf`), so v4 would never select the kernels.

Here `cpuf/include/cpuinfo_x86.h` fills the same five flags from gcc's `__builtin_cpu_supports` (libgcc's CPUID
probe, which also checks that the OS enabled the AVX-512 state in XCR0). This keeps the build offline with no
vendored library, and the binary uses the real CPU's flags. The v4 HEXL build also relaxes the configure test from
"compiles and runs on the build host" to "compiles", because the build host has no AVX-512. As a result:

- On an IFMA CPU, `bench_up_v4` uses the IFMA kernels. `HEXL_DISABLE_AVX512IFMA=1 ./bench_up_v4 5 5` turns them
  off, giving a same-binary A/B; `HEXL_DISABLE_AVX512DQ=1` turns off all AVX-512 kernels.
- The rest of the v4 binary (LaZer, Falcon, HEXL outside the dispatched kernels) is compiled for x86-64-v4. It needs
  AVX-512F/BW/DQ/VL at least and crashes with SIGILL without them. `run.sh` checks `avx512ifma` before it starts.

`build-info.txt` counts the `AVX512…<52>` (IFMA) kernel symbols linked into `bench_up_v4` (14 at `fd8600f`).

## Build (repo side)

Run from the repository root, on the dev host:

```sh
# once, needs network: docker build -t p6d-lazer-build:ubuntu24.04 pqz-core/research/upstream
scripts/capped pqz-core/research/upstream/static/build.sh <work dir> <LaZer clone at 3330e48>
#  -> <work dir>/pqz-bench-<git short sha>/ and <work dir>/pqz-bench-<git short sha>.tar.gz  (~5.5 MB)
```

Requirements: docker with the `p6d-lazer-build:ubuntu24.04` image, a local LaZer clone (any checkout that contains
`3330e48`, which includes `third_party/hexl-development.zip`), host clang and static glibc (`libc6-dev`).

The build is offline. Upstream builds in the container with `--network none`. The fork builds on the host with
clang, the compiler that `pqz-core/pqzl/build.sh` uses, because the image has none. Never commit the binaries, the work
dir or the tarball (`.gitignore`).

## Run (any x86-64 Linux, no dependencies)

Copy the tarball to the machine to measure, unpack it, and run `run.sh` from inside the unpacked directory:

```sh
scp pqz-bench-<sha>.tar.gz host:   &&   ssh host
tar xzf pqz-bench-<sha>.tar.gz && cd pqz-bench-<sha>
./run.sh            # N = 5 proves + 5 verifies per relation, every binary; ~9 min on the reference machine (N = 3: 5.3 min)
./run.sh 3 bench_up_v4 bench_fork     # fewer runs / a subset
CPU=5 ./run.sh      # pin to CPU 5 (default CPU 1; CPU= turns pinning off; skipped if taskset is missing)
```

`run.sh` prints the CPU model and the relevant `/proc/cpuinfo` flags (`aes vaes avx2 avx512f avx512dq avx512vl
avx512ifma avx512vbmi2`). It runs each binary once as `bench N N`: N proves with seeds 0..N-1, each followed by a
check verify, then N timed verifies. The table shows the medians (`p50`) of prove and verify for `R_REG` and
`R_TX` and the largest proof size. Output files: `results-<UTC stamp>.json` and the raw bench output in
`raw-<stamp>/`. A run that fails a verify or exits non-zero is marked `FAILED`.

Memory: upstream leaks, reaching about 2.1 GB max RSS for N = 5. The fork peaks at about 0.6 GB. For stable
numbers, use an otherwise idle machine and, if possible, the `performance` governor. Proofs differ between upstream
and the fork because the Gaussian samplers differ, so proof sizes can differ by a few bytes. Prove time barely
depends on the rejection count.

## Report back

Paste the `results-<stamp>.json` file (one JSON object: CPU, flags, N, per-binary medians, bytes and fails) and the
first line of `build-info.txt` (bundle sha) into the conversation or the TODO row.

## Licence: do not publish the tarball

The static upstream binaries link GMP and MPFR (LGPL-3.0+) and libstdc++ (GPL with the runtime exception) into one
executable. LGPL relinking duties apply as soon as the binary is distributed. LaZer itself is MIT and HEXL is
Apache-2.0. Copying the bundle to our own machines for private measurement is fine. Do not publish the tarball or
attach it to a release or a public issue (see also `pqz-core/README.md`).

## Reference machine

AMD Ryzen 5 7235HS (Zen 3+, AVX2, no AVX-512), 8 threads, 23 GB, Linux 7.0, pinned to CPU 1, under `scripts/capped`,
bundle `pqz-bench-fd8600f`, N = 3 (smoke test, 2026-10-13). Medians in ms:

| binary | R_REG prove | R_REG verify | R_TX prove | R_TX verify | R_REG bytes | R_TX bytes |
|---|---|---|---|---|---|---|
| `bench_up_v3` | 577 | 552 | 6,394 | 6,738 | 28,106 | 42,755 |
| `bench_up_v4` | skipped: no avx512ifma | | | | | |
| `bench_fork` | 1,280 | 1,056 | 15,563 | 13,881 | 28,085 | 42,770 |
| `bench_fork_v3` | 1,024 | 804 | 12,810 | 11,679 | 28,085 | 42,770 |

These match the cross-check (`../RESULTS.md`: upstream `-march=native` 622 / 566 / 6,623 / 6,621; fork as shipped
1,302 / 992 / 17,110 / 15,027). `results` JSON:

```json
{"bundle": "pqz-bench-fd8600f", "date": "20261013T025245Z", "cpu": "AMD Ryzen 5 7235HS", "flags": "aes avx2 vaes", "threads": 8, "mem_gb": 23, "kernel": "7.0.0-34-generic", "n": 3, "pinned_cpu": "1", "results": [
  {"bin": "bench_up_v3", "reg_prove_ms": 576.944, "reg_verify_ms": 552.063, "tx_prove_ms": 6393.558, "tx_verify_ms": 6738.188, "reg_bytes_max": 28106, "tx_bytes_max": 42755, "fails": 0, "exit": 0},
  {"bin": "bench_up_v4", "skipped": "no avx512ifma on this CPU"},
  {"bin": "bench_fork", "reg_prove_ms": 1280.373, "reg_verify_ms": 1055.570, "tx_prove_ms": 15563.286, "tx_verify_ms": 13880.817, "reg_bytes_max": 28085, "tx_bytes_max": 42770, "fails": 0, "exit": 0},
  {"bin": "bench_fork_v3", "reg_prove_ms": 1024.329, "reg_verify_ms": 804.456, "tx_prove_ms": 12809.524, "tx_verify_ms": 11678.774, "reg_bytes_max": 28085, "tx_bytes_max": 42770, "fails": 0, "exit": 0}
]}
```

(`threads` was 1 in the raw smoke output because `nproc` honours `OMP_NUM_THREADS=1`. `run.sh` now counts
`/proc/cpuinfo`.) `bench_up_v4` was not run here: there is no AVX-512 on this machine and no Intel SDE.
