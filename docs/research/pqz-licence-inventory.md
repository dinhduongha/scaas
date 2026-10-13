> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ licence inventory: third-party code, GMP / MPFR / HEXL absence, open questions (G-LIC step 1)

Written 2026-10-14 (owner, 2026-10-13: G-LIC step 1, the technical part). Gate G-LIC is defined in
`docs/contracts/pq-zether.md` (CTR-PQZ-01, "The licence gate **G-LIC**") and in the P6 roadmap
(`docs/superpowers/plans/2026-10-12-p6-roadmap.md`). This note lists what PQZ would ship, where each piece of
third-party code comes from and under which licence, proves from the built artifacts that GMP, MPFR and HEXL are
absent, and lists the gaps and the questions a lawyer must decide. **It draws no legal conclusion and records no
decision.** Base: `main` at `836c95c`, branch `glic-inventory`.

**[measured]** marks a fact from a run (pointed to). **[code]** marks a fact read in a file, manifest or lock file at
the given path. **[unknown]** marks something this inventory could not establish from the repository.

## 1. Summary

- **What ships** (if PQZ is released): `libpqz.a` / `libpqz.so` and a wasm module built from `pqz-core`; the Solidity
  verifiers `UAMldsaVerifier`, `UAFndsaVerifier`, `UASlhdsaVerifier` and their libraries; `clients/clientkeys` with
  `@noble/post-quantum`. Not shipped: the PQZH prototype crate, the bench and test binaries, the upstream
  cross-check builds (§2).
- **Third-party code in `pqz-core`**: LaZer `3330e48` (MIT, (c) 2022-2026 IBM) — 41 files in `lazer/` (20 identical
  to upstream, 21 modified), 2 codegen scripts, the generated parameter headers, and code in `src/pqz_rel.c` /
  `src/pqz_sv.c` that follow LaZer; plus LaZer's SHAKE128, whose header attributes it to public-domain Keccak code
  (§3). No other vendored library [code].
- **Absence proof**: in `libpqz.a`, `libpqz.so`, both `pqz.wasm` variants and the three bench / test binaries,
  0 symbol names and 0 strings match `/gmp|mpfr|hexl/i`. `libpqz.so` needs only `libc.so.6`. Neither wasm module
  has an import section. The same scan finds 620 / 560 matching symbols in the system `libgmp` / `libmpfr`
  [measured] (§6).
- **Notice**: `pqz-core/NOTICE` (new) carries the LaZer MIT text, the Keccak attribution and the list of
  retained and derived files. `pqz-core/lazer/LICENSE` is byte-identical to upstream's `LICENSE`. Neither upstream
  nor `pqz-core` has per-file licence headers in the LaZer files [code].
- **PQ signatures**: the three Solidity verifiers are SCaaS's own code (SPDX `LicenseRef-Vegan-Community-1.0`, no
  third-party marker). The clientkeys PQ and crypto dependencies are all MIT (`@noble/post-quantum` 0.7.1 and
  six more packages) [code] (§4).
- **PQZH** (not shipped): 71 crates in `Cargo.lock`, all permissive (MIT / Apache-2.0 dual, MIT, Zlib, CC0-1.0,
  Unicode-3.0). Plonky3 `p3-*` 0.8.0 are `MIT OR Apache-2.0` [code] (§5).
- **Gaps** (§7): 10 items. Most important: the AES S-box's code-text provenance is not recorded beyond "the same
  circuit as BearSSL's"; the PQZH crate declares `MIT OR Apache-2.0`, not the repository licence; the
  `xcheck/static` benchmark bundle statically links GMP / MPFR / glibc / libstdc++ / HEXL and must stay internal; a
  binary release must carry `NOTICE` by some channel (the binaries embed no notice).

## 2. What PQZ would ship

| Component | Shipped artifact | Built by | Status |
|---|---|---|---|
| PQZL prover / verifier | `libpqz.a`, `libpqz.so` (native), iOS / Android libraries (not built yet) | `pqz-core/build.sh native` | shipped if released |
| same, browser / wallet | wasm module, with (`pqz.wasm`) and without (`SV=0`) the specialised verifier | `pqz-core/build.sh wasm` | shipped if released |
| On-chain PQ signature verification | `UAMldsaVerifier`, `UAFndsaVerifier`, `UASlhdsaVerifier` (+ `MlDsa`, `Falcon512`, `SlhDsaSha2128s`, `Shake`, `PqNtt`, `PqUA`) | forge | deployed contracts |
| Client keys | `clients/clientkeys` (`src/pq.js` + npm deps) | node / esbuild | shipped (PQ part not in the portal bundle, §4.2) |
| PQZH prototype | `pqz-core/pqzh` (Rust, Plonky3) | cargo | **not shipped** (`publish = false`) |
| Bench / test / cross-check | `pqz_bench`, `kat_dump`, `pqz_sv_diff`, `xcheck/`, `kat/build-lazer-dump.sh` | scripts | **not shipped** |

[code] The current `pqz.wasm` links the bench harness `test/pqz_bench.c` with the library objects
(`build.sh`, `wasm()`); a product wasm module with only the C ABI does not exist yet. The absence check covers the
library and runtime objects such a module would contain; it must be re-run on the real module (gap 9).

## 3. `pqz-core`: third-party code

### 3.1 LaZer files in `pqz-core/lazer/` and `params/codegen/`

Upstream: <https://github.com/lazer-crypto/lazer> at `3330e487228f633eceb322807b13a596b516770f` (2026-09-28),
licence file `LICENSE` (MIT, "Copyright (c) 2022-2026 IBM"). The comparison below is `cmp` / `diff` of every file
against that checkout. "+a/−b" counts changed lines. "PQZ:" counts lines containing `PQZ`. "In libpqz" means
compiled through the unity file `src/pqz_lazer.c` or included by a compiled file.

**Headers** [code]: no LaZer source file carries a copyright or licence header, neither upstream (grep for
`copyright|spdx` over upstream `src/*.c src/*.h`: no file) nor here. Upstream states its licence only in `LICENSE`.
`shake128.c` has a provenance comment ("Based on the public domain implementation in crypto_hash/keccakc512/simple/
from http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public domain "TweetFips202" implementation ... by
Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe"). The pristine import (`c91b3ab`) of `grandom.c` also
credited fdlibm for its `exp`; that code was removed by the PQZ rewrite and no fdlibm text remains [code].

| File | Upstream path | In libpqz | vs upstream | PQZ: | Note |
|---|---|---|---|---|---|
| `LICENSE` | `LICENSE` | — | identical | 0 | MIT, (c) 2022-2026 IBM |
| `abdlop.c` | `src/abdlop.c` | yes | identical | 0 | added in `9ba594d` (not in `c91b3ab`) |
| `aes256ctr.c` | `src/aes256ctr.c` | yes | +296/−149 | 1 | rewritten: bitsliced AES, Boyar–Peralta S-box (gap 3) |
| `aes256ctr.h` | `src/aes256ctr.h` | yes | identical | 0 | |
| `brandom.c`, `brandom.h` | `src/` | yes | identical | 0 | |
| `bytes.c` | `src/bytes.c` | **no** | identical | 0 | retained, not compiled |
| `coder.c` | `src/coder.c` | yes | +39/−16 | 5 | bounded decoder |
| `config.h` | `config.h` | yes | +8/−1 | 4 | generic target, no intrinsics |
| `dcompress.c` | `src/dcompress.c` | yes | identical | 0 | |
| `dom.h` | `src/dom.h` | yes | identical | 0 | added in `c397a6d` |
| `grandom.c` | `src/grandom.c` | yes | +65/−162 | 5 | rewritten sampler (fixed-point `exp`) |
| `grandom.h` | `src/grandom.h` | yes | identical | 0 | |
| `int.c` | `src/int.c` | yes | +17/−19 | 3 | no `mpz_*` |
| `intmat.c`, `intvec.c`, `polymat.c` | `src/` | yes | +4/−0 each | 2 each | `PQZ_STDIO` guards |
| `intvec.h` | `src/intvec.h` | yes | identical | 0 | |
| `lazer-in1.h` | `src/lazer-in1.h` | yes | identical | 0 | assembled into `lazer.h` |
| `lazer-in2.h` | `src/lazer-in2.h` | yes | +81/−158 | 39 | HEXL / GMP declarations removed; Falcon prototypes remain, undefined and unreferenced |
| `lnp-quad.c` | `src/lnp-quad.c` | yes | +8/−1 | 3 | |
| `lnp-quad-eval.c` | `src/lnp-quad-eval.c` | yes | +4/−4 | 4 | |
| `lnp-quad-many.c` | `src/lnp-quad-many.c` | yes | +0/−1 | **0** | `#include <mpfr.h>` removed, unmarked (gap 2) |
| `lnp-tbox.c` | `src/lnp-tbox.c` | yes | +224/−77 | 53 | soundness fixes (lazer#24, #25), trace hooks |
| `lnp-tbox.h` | `src/lnp-tbox.h` | yes | identical | 0 | |
| `memory.c` | `src/memory.c` | yes | +1/−65 | 1 | arena instead of malloc |
| `memory.h` | `src/memory.h` | yes | +12/−8 | 2 | |
| `mont.h` | `src/mont.h` | **no** | identical | 0 | retained, included nowhere |
| `poly.c` | `src/poly.c` | yes | +31/−368 | 11 | CRT / HEXL ring code replaced by `src/pqz_ntt.c` |
| `poly.h` | `src/poly.h` | yes | identical | 0 | |
| `polyring.c` | `src/polyring.c` | yes | identical | 0 | |
| `polyvec.c` | `src/polyvec.c` | yes | +29/−0 | 4 | |
| `rejection.c` | `src/rejection.c` | yes | +103/−171 | 2 | rewritten without MPFR |
| `rng.c`, `rng.h` | `src/` | yes | identical | 0 | |
| `shake128.c`, `shake128.h` | `src/` | yes | identical | 0 | public-domain Keccak attribution (above) |
| `spolymat.c`, `spolyvec.c` | `src/` | yes | +18/−2 each | 3 each | |
| `stopwatch.h` | `src/stopwatch.h` | yes | +8/−0 | 2 | no stdio when freestanding |
| `urandom.c`, `urandom.h` | `src/` | yes | identical | 0 | |
| `params/codegen/codegen.sage` | `scripts/codegen.sage` | — (generator) | +2/−1 | 1 | |
| `params/codegen/lnp-tbox-codegen.sage` | `scripts/lnp-tbox-codegen.sage` | — (generator) | +28/−3 | 6 | |

Totals: 41 files besides `LICENSE`; 20 identical, 21 modified; 39 compiled into `libpqz`. The tbox codegen output
`params/pqz_{reg,tx,burn,ds,dr}_params.h` is compiled in; each begins `// auto-generated by lnp-tbox.sage.` [code].

### 3.2 `pqz-core/src/` and other shipped sources

| File | Origin [code] |
|---|---|
| `pqz_rel.c` | SCaaS; its proof encoding follows LaZer `src/lin-proofs.c` (`lnp_tbox_encproof` / `decproof`), whose file is not in `lazer/` (the header says so: "LaZer lin-proofs.c's ... MIT") — now listed in `NOTICE` |
| `pqz_sv.c` | SCaaS; re-implements LaZer's `lnp-tbox.c` verification for the five relations; its table AES builds its tables at run time (`aes_tables`); optional AES-NI path via `<immintrin.h>` intrinsics |
| `pqz_mpn.h` | SCaaS; "the limb operations LaZer took from GMP's mpn layer, rewritten in C99 without GMP", under `pqz_mpn_*` names (lawyer item 4) |
| `pqz_ntt.c`, `pqz_ntt.h`, `pqz_fixexp.h` (Taylor series, constants `2^63/k!`), `pqz_arena.c`, `pqz_rt.h`, `pqz_glue.h`, `pqz_int.h`, `pqz.h`, `pqz_lazer.c` | SCaaS |
| `pqz_aes_gen.h` | generated by `gen_aes.py` (SCaaS) |
| `pqz_wasm_rt.c`, `freestanding/string.h` | SCaaS: `memcpy` / `memset` / `memmove` / `memcmp` and the 128-bit helpers clang emits on wasm32, in place of libc and compiler-rt |

No HEXL, FLINT, GMP, MPFR, BLAKE, Falcon or other library source is present in `pqz-core/lazer` or `pqz-core/src`
(grep for `falcon|hexl|mpfr|gmp` finds only comments, the `GMP_NUMB_BITS` macro in `pqz_mpn.h`, and the Falcon
prototypes in `lazer-in2.h`) [code]. Upstream's `third_party/` (HEXL `hexl-development.zip`, Apache-2.0;
`Falcon-impl-20211101.zip`, MIT "(c) 2017-2020 Falcon Project"; `estimator.py`) is not vendored [code].

### 3.3 Toolchain pieces in the shipped artifacts

| Artifact | Toolchain | What the toolchain puts in | Evidence |
|---|---|---|---|
| `libpqz.a` | clang 18.1.3 | only the five objects `pqz_lazer.o pqz_ntt.o pqz_arena.o pqz_rel.o pqz_sv.o`; external references `memcpy`, `memset`, `__stack_chk_fail` | `ar t`, `check_symbols.sh` [measured] |
| `libpqz.so` | clang 18.1.3 `-shared`, system linker | the system's C start files and a dynamic dependency on `libc.so.6` (glibc); undefined `memcpy`, `memset`, `__stack_chk_fail`, weak `__cxa_finalize`, `__gmon_start__` (gprof hook of the start files, not GMP), `_ITM_*` | `readelf -d`, `nm -D` [measured] |
| `pqz.wasm` (both) | clang 18.1.3 `--target=wasm32-unknown-unknown -ffreestanding`, `wasm-ld-18` (LLD 18.1.3) | no libc, no compiler-rt (`pqz_wasm_rt.c` replaces both); no import section | `build.sh`, section headers [measured] |

LLVM (clang, LLD) is licensed Apache-2.0 WITH LLVM-exception; this inventory did not read the toolchain's licence
files on this machine [unknown, as a file check]. The wasm modules contain only code compiled from `pqz-core`
sources plus what `wasm-ld` synthesises (no library archive is linked).

## 4. PQ signature side

### 4.1 Solidity verifiers

| Contract / library | File | Licence header | Origin [code] |
|---|---|---|---|
| `UAMldsaVerifier`, `MlDsa` (ML-DSA-44 / 65) | `smartcontracts/evm/src/ua/MlDsa.sol` | `LicenseRef-Vegan-Community-1.0` | SCaaS, written from FIPS 204 Algorithm 8 and the EIP-8051 / EIP-8355 key layouts (P6a T4, `121271f`) |
| `UAFndsaVerifier`, `Falcon512` | `.../FnDsa.sol` | same | SCaaS, from the Falcon round-3 specification v1.2 Algorithm 16 and EIP-8052 (P6a T3, `a121068`) |
| `UASlhdsaVerifier`, `SlhDsaSha2128s` | `.../SlhDsa.sol` | same | SCaaS, from FIPS 205 (P6a T2, `4ad20be`) |
| `Shake`, `PqNtt`, `PqUA` | `.../Shake.sol`, `PqNtt.sol`, `PqUA.sol` | same | SCaaS (P6a) |

No file contains a "ported", "adapted", "based on" or third-party copyright marker; the P6a plan
(`docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md`) names the specifications and EIP texts as sources and
`@noble/post-quantum` only as an independent cross-check [code]. Constants such as the FIPS 204 `zetas` table are
computed values from the standard.

Test vectors (repository data, not deployed): `smartcontracts/vectors/ua/pq_external.json` imports NIST
ACVP-Server `gen-val` files (commit `975de31`) and EIP assets at `ethereum/EIPs@3aea9f3` (EIP-8051 `mldsa_nist.rsp`,
EIP-8052 KATs, EIP-8355 `test-vectors.json`, whose case names cite Wycheproof), each with its SHA-256 [code]. The
licences of those files were not checked [unknown] (gap 7).

### 4.2 `clients/clientkeys` npm packages

From `package-lock.json` (lockfileVersion 3) [code]; the `LICENSE` file of every production package was read in the
installed `node_modules` and agrees [code]. Raw table: `pqz-core/glic/runs/clientkeys-npm-licences.tsv`.

| Package | Version | Licence | Scope | Copyright line in `LICENSE` |
|---|---|---|---|---|
| `@noble/post-quantum` | 0.7.1 | MIT | prod | (c) 2024 Paul Miller |
| `@noble/hashes` | 2.4.0 | MIT | prod | Paul Miller |
| `@noble/curves` | 2.4.0 | MIT | prod | Paul Miller |
| `@noble/ciphers` | 2.4.0 | MIT | prod (dependency of `@noble/post-quantum`) | (c) 2022 Paul Miller **and (c) 2016 Thomas Pornin** |
| `@scure/base`, `@scure/bip32`, `@scure/bip39` | 2.4.0 | MIT | prod | Paul Miller |
| `esbuild` + 25 `@esbuild/*` platform packages | 0.28.2 | MIT | dev (build tool) | — |

The package itself is `"license": "SEE LICENSE IN ../../LICENSE"`. The `build` script bundles `passkey-signer.js`,
`seed-signer.js` and `zether-keys.js` with `--legal-comments=eof`; `src/pq.js` is not in that bundle ("Not in the
portal bundle", P6a plan) [code]. No other manifest in the repository (`go.mod`, `Cargo.toml`, `package.json`,
`pyproject.toml`) names a PQ library [code].

## 5. PQZH prototype crate (not shipped)

`pqz-core/pqzh/Cargo.toml`: `license = "MIT OR Apache-2.0"`, `publish = false`, toolchain 1.97.1 [code]. Every
package of `Cargo.lock` from `cargo metadata --offline --locked` (raw: `pqz-core/glic/runs/pqzh-cargo-licences.tsv`,
71 packages including `pqzh` itself) [code]:

| Licence (as declared) | Packages |
|---|---|
| `MIT OR Apache-2.0` / `Apache-2.0 OR MIT` / `MIT/Apache-2.0` | 61, among them all Plonky3 crates `p3-*` 0.8.0, `rand` 0.10.3, `sha3` 0.10.8, `postcard` 1.1.1, `serde` 1.0.229 |
| `MIT` | 7: `crunchy` 0.2.4, `generic-array` 0.14.7, `libm` 0.2.16, `spin` 0.12.3, `tracing` 0.1.44, `tracing-attributes` 0.1.31, `tracing-core` 0.1.36 |
| `Zlib` | 1: `foldhash` 0.2.0 |
| `CC0-1.0` | 1: `tiny-keccak` 2.0.2 |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 1: `unicode-ident` 1.0.27 (build-time, proc-macro chain) |

No copyleft licence appears. The declared crate licence differs from the repository licence (gap 5).

## 6. GMP / MPFR / HEXL absence proof

Run: `scripts/capped pqz-core/glic/absence.sh > pqz-core/glic/runs/absence-2026-10-14.txt 2>&1` at commit
`025cc90` (clean tree). The script builds `./build.sh all` and `SV=0 ./build.sh wasm` from scratch into
`pqz-core/build/glic/` (git-ignored; nothing built is committed), prints the SHA-256 of every artifact, then for each
artifact: `llvm-nm-18 -A` (all symbol names, defined and undefined), `readelf -d` (`DT_NEEDED`), `ar t`,
`llvm-objdump-18 --section-headers` and `llvm-nm-18 --undefined-only` (wasm imports), and `strings -a`; every
filter is `grep -iE 'gmp|mpfr|hexl'`. Two runs (one before the commit) gave identical SHA-256 for all seven
artifacts [measured].

| Artifact | symbol matches | string matches | linked libraries / imports |
|---|---|---|---|
| `libpqz.a` | 0 | 0 | members: 5 pqz objects; `check_symbols.sh`: only `memcpy memset __stack_chk_fail` outside |
| `libpqz.so` | 0 | 0 | `NEEDED libc.so.6` only |
| `pqz.wasm` (SV=1) | 0 | 0 | no import section; no undefined symbol |
| `pqz.wasm` (SV=0) | 0 | 0 | no import section; no undefined symbol |
| `pqz_bench`, `kat_dump`, `pqz_sv_diff` | 0 each | 0 each | `NEEDED libc.so.6` only |
| control: system `libgmp.so.10` | 620 | 623 | — |
| control: system `libmpfr.so.6` | 560 | 737 | — |

[measured] (`pqz-core/glic/runs/absence-2026-10-14.txt`). The positive control shows the filters find GMP and MPFR
where they are. HEXL has no system library here; HEXL symbols are C++ names in namespace `intel::hexl`, which the
same filter matches (upstream's `bench_up_v4` is counted by `nm -C ... | grep 'AVX512.*<52'` in
`xcheck/static/build.sh`) [code]. Every `pqz-core/build.sh` run also fails on any external reference other than
`memcpy`, `memset`, `__stack_chk_fail`, `__stack_pointer` (`check_symbols.sh`) [code].

**Repo tools that do use GMP / MPFR / HEXL** (none ships anything) [code]:

| Tool | Links | Output | Kept |
|---|---|---|---|
| `kat/build-lazer-dump.sh` | upstream LaZer statically with GMP, MPFR, HEXL, libstdc++ | `lazer_dump-v3/v4` (golden KAT dump) | binary git-ignored (`lazer_dump-*`); only the JSON `kat/lazer-3330e48.json` is committed |
| `xcheck/build-upstream.sh`, `build-up-bench.sh`, `build-micro.sh`, `build-prof.sh` (image `xcheck/Dockerfile`: `libgmp-dev`, `libmpfr-dev`) | upstream LaZer + GMP / MPFR / HEXL | timing and profile binaries | results only (`runs/`, `prof/`); binaries not kept |
| `xcheck/static/build.sh` | upstream statically with glibc, GMP, MPFR, libstdc++, HEXL (and LaZer's Falcon) | tarball `pqz-bench-<sha>.tar.gz` "for measuring on other machines" | git-ignored (gap 6) |
| `params/run_e_s1.sh`, `params/codegen/run.sh` | SageMath image, lattice-estimator `53da598` (not vendored) | estimator text, generated headers | text and headers committed |

These are local scripts; `.github/workflows/ci.yml` references none of them [code].

## 7. Gaps found

1. **Binary distributions carry no notice by themselves.** `libpqz.so` and the wasm modules embed no licence text
   (MIT asks the notice be included "in all copies or substantial portions"). A release must ship `pqz-core/NOTICE`
   beside them or in the app's licence screen [code]. *Owner / release process.*
2. **One unmarked modification.** `lazer/lnp-quad-many.c` differs from upstream by one removed line
   (`#include <mpfr.h>`) without a `PQZ:` comment; all other modified files carry `PQZ:` marks [code]. The MIT text
   has no change-marking condition; the README promises the marks. **Resolved 2026-10-14 (owner): `PQZ:` mark added.**
3. **AES S-box provenance.** `lazer/aes256ctr.c` (commit `405a3e3`) implements the Boyar–Peralta circuit; its
   comment says "the same circuit as BearSSL's constant-time AES". Whether the code text was transcribed from
   BearSSL's source (MIT, Thomas Pornin) or from the published circuit is not recorded [unknown]. If from BearSSL,
   `NOTICE` needs BearSSL's MIT notice. **Resolved 2026-10-14 (owner): BearSSL's MIT notice added to `NOTICE` as a precaution (§4 there).**
4. **LaZer code outside `lazer/`.** `src/pqz_rel.c` (from `lin-proofs.c`) and `src/pqz_sv.c` (following
   `lnp-tbox.c`) contain LaZer-derived code in SCaaS-headed files. Now listed in `NOTICE`; not otherwise marked.
5. **PQZH declared licence.** `pqz-core/pqzh/Cargo.toml` says `MIT OR Apache-2.0`; the repository licence is the
   Vegan Community License 1.0 [code]. Not shipped, but the declaration is inconsistent. **Resolved 2026-10-14 (owner): `license-file = "../../LICENSE"`.**
6. **`xcheck/static` bundle.** The tarball statically links GMP and MPFR (LGPL), glibc (LGPL), libstdc++ (GPL with
   the GCC runtime exception), HEXL (Apache-2.0) and LaZer's Falcon (MIT) [code: README and build script]. It is
   built for the owner's own machines and is git-ignored; handing it to a third party would be a distribution of
   those libraries with their duties (LGPL relinking, Apache NOTICE). **Owner 2026-10-14: the bundle is never uploaded or published (no built binaries on GitHub); it stays on the owner's machines.**
7. **Test-vector licences unknown.** `pq_external.json` holds data from NIST ACVP-Server and from EIP assets
   (including Wycheproof-derived cases) in a public repository; their licence terms were not checked [unknown].
8. **Retained, unused files.** `lazer/bytes.c` and `lazer/mont.h` are kept but not compiled [code]. Harmless; they
   still fall under the LaZer notice.
9. **No product wasm module yet.** Today's `pqz.wasm` includes the bench harness. Re-run `glic/absence.sh` (and the
   `NOTICE` check) on the release module and on the iOS / Android libraries once they exist.
10. **Toolchain licence files not read.** LLVM 18.1.3 (clang, LLD) and the system start files / glibc that
    `libpqz.so` uses were identified by version only [unknown, as a file check].

## 8. For the lawyer

Questions only; nothing here is an answer.

1. **LaZer, MIT without a patent grant.** Does the MIT licence from IBM (`lazer/LICENSE`) give SCaaS any patent
   licence, express or implied, for the retained and modified LaZer code? Does IBM hold patents or applications that
   read on LaZer's protocols (`lnp-tbox`, ABDLOP commitments) as used by PQZ, and in which jurisdictions?
2. **LNP22-family techniques.** The proof system is the lattice ZK framework of Lyubashevsky, Nguyen and Plançon
   (CRYPTO 2022) and its LaZer implementation; LaZer's copyright holder is IBM. Is a freedom-to-operate search
   needed for these techniques independently of the code licence, and for which markets?
3. **Licence combination.** Can MIT-licensed code (LaZer, `@noble/*`) and the Keccak public-domain code be combined
   into and distributed with SCaaS code under the Vegan Community License 1.0, keeping the MIT notice (as `NOTICE`
   does)? Is `NOTICE` plus `lazer/LICENSE` sufficient attribution for source and for binary distribution?
4. **GMP API names.** `src/pqz_mpn.h` re-implements the semantics of the GMP `mpn_*` calls LaZer used, under new
   names, without GMP code. Does that raise any LGPL question? (Technical fact: no GMP code or symbol is in any
   artifact, §6.)
5. **ML-DSA (FIPS 204), FN-DSA / Falcon, SLH-DSA (FIPS 205).** What is the patent status of each scheme as SCaaS
   uses it (own Solidity verifiers; `@noble/post-quantum` for keys and signing), including any patent statements or
   licences NIST published for its PQC standards, and the status of Falcon before its FIPS (206) is final?
6. **Lattice-based encryption in PQZ.** Do the PQZ encryption and relation design (pq-zether.md) raise patent
   questions of their own beyond LaZer / LNP22?
7. **AES S-box (gap 3).** If the circuit text came from BearSSL, is MIT attribution sufficient? Is a published
   gate-level circuit protectable as such?
8. **Test data (gap 7).** Under which terms may NIST ACVP, EIP and Wycheproof vectors be redistributed in a public
   repository?
9. **Internal benchmark bundle (gap 6).** Does copying the statically linked bundle to machines the owner controls
   count as distribution under the LGPL?

## 9. Files

- `pqz-core/NOTICE` — third-party notices (new).
- `pqz-core/glic/absence.sh` — build + scans; `pqz-core/glic/runs/absence-2026-10-14.txt` — its output.
- `pqz-core/glic/runs/pqzh-cargo-licences.tsv`, `pqz-core/glic/runs/clientkeys-npm-licences.tsv` — raw tables.
