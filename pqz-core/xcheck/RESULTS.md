# P6d upstream timing cross-check: LaZer 3330e48 vs the pqz-core fork on R_REG / R_TX

Question: is the R_TX slowness (fork: prove ~17 s / verify ~15 s) caused by the fork's rewrite, or is it
inherent to the statement as LaZer runs it? Measured 2026-10-13. No product code was changed; nothing was committed.

## Setup

- Machine: AMD Ryzen 5 7235HS (Zen 3+, AVX2, **no AVX-512**), 8 threads, 23 GB RAM, Linux 7.0. Single-threaded runs,
  each under `scripts/capped`. Other docker services (odoo, ollama, redpanda, ...) were running, so expect noise.
- **Upstream**: LaZer `3330e48` (`lazer-up/`, copy of `$S/lazer`), built offline in the local image
  `p6d-lazer-build:ubuntu24.04` (`--network none`): gcc 13.3.0, cmake 3.28.3, static libgmp-dev 6.3.0 and
  libmpfr-dev 4.2.1, HEXL from `third_party/hexl-development.zip`. Flags are upstream's Makefile defaults
  `-O3 -g -march=native -mtune=native -fomit-frame-pointer` (here native = znver3, AVX2, no AVX-512) plus
  `-fno-strict-aliasing` (the `aes256ctr-amd64.c` bug) and `-DNDEBUG`. config.h: `TARGET_AMD64` (AES-NI),
  `ASSERT_DISABLED`. HEXL configure found no AVX-512 (`HEXL_HAS_AVX512* 0`), so it takes its scalar path.
  HEXL's `cpu_features` (a GitHub fetch at configure time) is replaced by a header stub
  (`stub/cpuf/`) that reports every AVX-512 flag as false. On this CPU the real library would report the same,
  so the stub does not change the runtime path.
- **Statement**: the fork's own R_REG / R_TX builder `src/pqz_rel.c` and bench `test/pqz_bench.c` (fork HEAD
  `b2402b5`, snapshot in `fork/`) are compiled **unchanged in logic** against upstream LaZer through
  `shim/` (malloc instead of the arena, `lazer_init()`, two upstream-API substitutions in `shim/up_rel.c`: no
  bounded decoder `coder_dec_begin_len` / `cstate->err`). The run uses the same params headers
  `params/pqz_{reg,tx}_params.h` (q = 2^42 − 215, d = 64, L = 4, R_TX m1 = 146 + 7, m2 = 68, kmsis = 23,
  kmlwe = 33, nbin = 15, n = [32,32,32,32,1,1,1], nprime = 1), the same 64 quadratic + 80 evaluation equations, and
  the same witness and seeds. **Upstream accepts the fork's header as is**: it carries upstream's CRT data
  (2 × 50-bit moduli for d = 64, `moduli_d64, 2`), so no q substitution was needed. Every upstream proof verifies
  (`fails: 0`). Its proof sizes match the fork's.
- Bench copy `shim/bench.c` = `test/pqz_bench.c` with three changes: adversarial verifies are skipped (upstream has
  no bounded decoder), it prints per-proof time / length / FNV hash, and `XC_TXONLY` skips R_REG for profiling.
- **Fork** variants (same snapshot, `build-fork.sh`, clang 18.1.3):
  `as` = `./build.sh native` as shipped (clang -O2, generic x86-64, PQZ_ASSERT=1);
  `noassert` = + `-DPQZ_ASSERT=0`; `native` = + `-O3 -march=native -mtune=native` (upstream's flags).
- Runs: `bench 5 5`, i.e. 5 proves (seeds 0..4, each followed by a verify) + 5 timed verifies per relation. Values
  are medians.

## Results (median of 5, ms)

| | upstream LaZer (gcc -O3 native, HEXL, GMP, AES-NI) | fork as shipped (clang -O2) | ratio fork/up | fork -O3 native, no asserts | ratio |
|---|---|---|---|---|---|
| R_REG prove | **622** | 1,302 | 2.1× | 985 | 1.6× |
| R_REG verify | **566** | 992 | 1.75× | 784 | 1.4× |
| R_TX prove | **6,623** (6,444–7,082) | 17,110 (15,551–17,613) | **2.6×** | 13,497 | 2.0× |
| R_TX verify | **6,621** (max 6,864) | 15,027 | **2.3×** | 12,076 | 1.8× |
| R_TX proof bytes | 42,736–42,755 | 42,734–42,770 | = | same | |
| R_REG proof bytes | 28,064–28,106 | 28,070–28,107 | = | same | |
| peak memory | 2.1 GB max RSS (upstream leaks; 1 prove+verify: 0.9 GB) | arena peak 612 MB | | | |

`noassert` (clang -O2, PQZ_ASSERT=0): R_TX prove 16,454 / verify 14,465, R_REG 1,256 / 981, so the fork's
always-on asserts cost about 4 %. Compiler flags (-O3 -march=native) cost a further ~18 %.

The proofs are not byte-identical across backends. The Gaussian sampler and rejection step differ (fork: integer
/ fixed point; upstream: MPFR), so rejection-loop counts differ per seed. This does not matter here: prove time is
almost flat in the number of tries (fork: 4 tries 15.6 s, 18 tries 17.6 s, ≈ 0.15 s per try; upstream's 5 seeds
span 6.4–7.1 s).

## Per-operation microbench (`shim/micro.c`, same source both sides, ring pqz_tx_ring, median of 7)

| op | upstream | fork as | fork native | fork/up (as) |
|---|---|---|---|---|
| poly_mul, coeff in → coeff out (2 fwd + pointwise + 1 inv) | 6.87 µs | 3.28 µs | 2.22 µs | **0.48×** (fork faster) |
| poly_mul pointwise, both already in NTT/CRT form | 0.31 µs | 1.79 µs | 1.07 µs | **5.8×** |
| poly_tocrt (forward) incl. 0.1 µs copy | 1.20 µs | 0.57 µs | 0.48 µs | 0.48× |
| polyvec_mul A1(23×153, NTT form) · s1(153, coeff), result to coeff | 1.42 ms | 6.61 ms | 3.71 ms | **4.6×** |
| rng_urandom AES-256-CTR, 1 MiB | 0.128 ms (AES-NI) | 61.0 ms (bitsliced) | 74.5 ms | 480× |

## Profile (gprof, R_TX, 1 prove + 1 verify, `XC_TXONLY=1 bench 1 0`; perf unavailable: perf_event_paranoid = 4)

Total sampled self time: upstream 13.3 s, fork (clang -O2 -pg) 27.6 s. Delta: 14.3 s.

| upstream top (self s) | | fork top (self s) | |
|---|---|---|---|
| HEXL EltwiseMultMod (pointwise) | 2.15 | **basemul16** (pointwise, 27.4 M calls) | **12.72** |
| int_mod | 1.91 | **spolymat_sort** (insertion sort `pqz_qsort`, 24 calls) | **4.52** |
| spolymat_set | 1.26 | intvec_set | 1.81 |
| _poly_alloc_polymat (malloc) | 0.98 | spolymat_insert_elem | 1.00 |
| poly_scale | 0.86 | int_mod | 0.99 |
| __modti3 | 0.84 | intvec_add | 0.82 |
| intvec_redc / intvec_add | 0.68 / 0.68 | pqz_red128 | 0.74 |
| _int_malloc | 0.52 | poly_scale | 0.71 |
| __ieee754_log2l | 0.43 | AES (gfmul + subword + sbox) | 0.43 |

Attribution of the 14.3 s delta (gprof self time; the remaining LaZer code is the same on both sides):
- **Pointwise products in the NTT domain: about +11 s (≈ 75–80 %).** The fork's incomplete NTT mod
  q = 2^42 − 215 (X^64 + 1 splits into only 4 factors, q ≡ 9 mod 16) leaves four degree-16 base multiplications
  per product: 4 × 256 64×64→128-bit multiplies with u128 accumulators (`basemul16`; reduction is already lazy).
  Upstream does 2 CRT primes × 64 Barrett mulmods (HEXL scalar). Microbench: 5.8× per pointwise product, 4.6× on
  the A1·s1 product. These products dominate LaZer's dot products and Schwartz–Zippel accumulation, where operands
  stay in NTT form. A full multiplication from coefficient form is **faster** on the fork (no GMP CRT
  reconstruction), but that is not the hot path.
- **Sparse-matrix sort: about +3–4 s (≈ 25 %).** The fork's `pqz_qsort` insertion sort (`spolymat_sort` 4.5 s +
  `spolymat_insert_elem` 1.0 s) against upstream's libc qsort (not visible in its profile beyond `spolymat_set` 1.3 s).
- **AES-256-CTR: ≈ 0.4 s (≈ 1.5 %).** It is 480× slower per MiB, but the R_TX PRG volume is small.
- **No GMP, arena, integer Gaussian, fixed-point rejection:** neutral to favourable. The fork's int_mod /
  int arithmetic costs less than upstream's (int_mod 1.0 vs 1.9 s, no malloc/free ≈ 1.5 s on upstream).
- Asserts ≈ 4 %; clang -O2 generic against -O3 -march=native ≈ 18 % (fork-native vs fork-as).

## Against the kill criteria (this machine, upstream as fast as it builds here)

| | upstream R_REG | upstream R_TX | threshold |
|---|---|---|---|
| prove | 0.62 s | 6.6 s | ≤ 3 s desktop |
| verify (median; p99 is higher) | 0.57 s | 6.6 s | p99 ≤ 50 ms |

Upstream LaZer does not meet either R_TX threshold on this machine: prove is 2.2× over 3 s and verify is ~130×
over 50 ms. Upstream R_REG meets the prove threshold but its verify is ~11× over 50 ms. In upstream's own
profile, pointwise multiplication (HEXL) is only ~16 %. Most of its time is LaZer's generic sparse-matrix /
Schwartz–Zippel bookkeeping, int arithmetic and malloc. A faster pointwise kernel (e.g. HEXL's AVX-512 IFMA
path, not available on this CPU) would therefore leave R_TX at several seconds. That part of the cost belongs to
the tbox statement shape (m1 + Z + l = 153-dimensional quadratic forms, 64 quadratic + 80 evaluation equations)
as LaZer evaluates it, for prover and verifier alike.

## Caveats

- AVX2 only: no AVX-512 here, so HEXL's IFMA / AVX-512 NTT and mulmod kernels were not exercised. On an AVX-512
  machine upstream's ~2.2 s of pointwise / NTT time would shrink. The rest of upstream would not.
- Same q (2^42 − 215) on both sides, with no substitution. Upstream reaches it through its CRT path (2 × 50-bit
  primes), which is why its NTT is complete while the fork's mod-q NTT is incomplete (L = 4).
- Compilers differ: upstream gcc 13.3 -O3 -march=native, fork clang 18 -O2 generic (as shipped). The
  `fork native` column removes most of the flag difference (ratio 2.0× / 1.8× for R_TX).
- Noise: a busy host (other containers). Upstream R_TX prove varied 6.44–7.08 s over 5 seeds. STATUS.md reports
  ±20 % between runs. Only 5 samples, so "p99" is not meaningful. Medians are reported.
- Upstream leaks memory in this harness (no arena, LaZer's known leaks): max RSS 2.1 GB after 15 R_TX
  proves/verifies. malloc cost is included in upstream's times.
- Upstream was not run on adversarial proofs (no bounded decoder).
- gprof uses -pg builds (prove + verify combined). HEXL / GMP / libc are sampled but not instrumented. The fork's
  -pg build is clang -O2 with asserts on, as shipped.

## Files and commands (all under `$S/xcheck/`)

- `build-upstream.sh` → `lazer-up/liblazer.a` + HEXL; `build-info-upstream.txt`, `hexl-cmake.log`, `lazer-build.log`
- `build-up-bench.sh` → `bench_up` (static); `build-fork.sh` → `bench_fork_{as,noassert,native}`
- `build-micro.sh` → `micro_up`, `micro_fork_{as,native}`; `build-prof.sh` → `bench_{up,fork}_prof`
- runs: `scripts/capped /usr/bin/time -f 'maxrss_kb %M wall %e' ./bench_X 5 5` → `runs/*.json`, `runs/*.err`;
  `scripts/capped ./micro_X` → `runs/micro_*.json`; `XC_TXONLY=1 ./bench_X_prof 1 0` + `gprof -b -p` → `prof/flat.*.txt`
- shims and copies: `shim/` (`memory.h`, `shim.c`, `up_rel.c`, `bench.c`, `micro.c`), `stub/cpuf/`, `fork/` (HEAD
  snapshot `b2402b5`, `git archive`; the p6d worktree was only read).
