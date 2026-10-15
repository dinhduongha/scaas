# pqz-core directory layout — proposal (2026-10-15)

**Status: controller proposal, not applied; the owner decides.** Owner 2026-10-15: "pqz-core's folder organisation isn't
good." This file describes today's tree, what is wrong with it, a proposed tree, every path reference the move would
change, a history-preserving `git mv` plan (nothing deleted — owner rule "backup, not delete"; experiment code stays
in the repository — owner rule "keep experiment code"), risks and an order. It is docs only: no file was moved. Four
other branches edit pqz-core now (`p6e-a5`, `pqz-artifact2`, `p6-anon-s`, `p6f`), so the move waits until they merge.
The rewritten front door is [pqz-core/README.md](../../../pqz-core/README.md); its last section "Old README → new
locations" below shows that nothing of the previous README was lost.

## 1. Today's tree (main `4ab2180`, tracked files per directory)

| Path | Files | System | What it is | Kind |
|---|---|---|---|---|
| `build.sh`, `check_symbols.sh`, `check_tbox_fixes.sh` | 3 | PQZL | build, symbol scan, tbox / z21 regression check | tool |
| `src/` | 17 | PQZL | the rewritten layers, relations, keys, specialised verifier, C ABI `pqz.h` | core |
| `lazer/` | 42 | PQZL | LaZer `3330e48` subset, modified in place (`PQZ:`) | core |
| `params/` | 41 | PQZL | codegen, relation specs, generated headers, sizing; `anon/` (P6-ANON sketches) | core + tool |
| `kat/` | 4 | PQZL | arithmetic-layer KAT against upstream | tool |
| `test/` | 12 | PQZL | bench, wasm runner, keys KAT, SV differential and fuzz harnesses, runs | tool |
| `sv/` | 156 | PQZL | specialised-verifier checks and bench, `review/` reproducers, runs | tool + measurement |
| `sz/`, `l2dom/` | 3 + 3 | PQZL | tbox-finding PoCs, run by `check_tbox_fixes.sh` | tool (spike origin) |
| `rel3/` | 138 | PQZL | the PQZL measurement round (`relfix.sh`), runs | measurement |
| `opt/` | 36 | PQZL | P6d-2 optimisation bench, gprof, ASan, microbenches, runs | measurement |
| `floor/` | 12 | PQZL | verifier-floor microbenchmarks and cost model | measurement |
| `xcheck/` | 38 | PQZL | upstream LaZer vs fork (`shim/` also used by `artifact/ --upstream`) | measurement |
| `pqzh/` top (`Cargo.toml`, `src/`, `tests/`, `examples/`, `wasm/`, `runs/`, `sol/`, `pqzh_count.py`, `counts.txt`) | ≈ 230 | PQZH | the Plonky3 STARK crate, its runs, Solidity / StarkEx cost models | backup |
| `pqzh/ligero/` | 171 | PQZH | crate `pqzh-ligero`, THE PQZH backend | core |
| `pqzh/xcheck/` | 4 | PQZH | C ↔ Rust statement cross-check (Ligero and STARK) | tool |
| `stmt/` | 27 | both | `pqz-stmt` | core |
| `ffi/` | 105 | both | `pqz-ffi` (precompile), vectors generator | core |
| `artifact/` | 73 | both | reproducibility package | tool |
| `glic/` | 4 | both | G-LIC absence scan and licence tables | tool |
| (`fuzz/`) | — | both | continuous fuzzing, on branch `p6e-a5` | tool |

## 2. Problems

1. **Core, tools, spikes and backups are siblings.** A reader sees 17 top-level directories and cannot tell that
   `src/ lazer/ params/` ship while `opt/ floor/ rel3/ xcheck/` are measurement harnesses and `pqzh/` (top) is a
   rejected backend.
2. **The PQZL core is spread** over `src/ lazer/ params/ kat/ test/ sv/` plus three scripts at the top, while PQZH has
   a directory of its own; nothing says "this is PQZL".
3. **`pqzh/` holds both the STARK backup and the Ligero core**: the backup crate's `Cargo.toml` and `src/` sit at the
   top of `pqzh/`, the production crate is nested one level below it in `pqzh/ligero/`.
4. **Measurement harnesses sit at the top level** next to the core (`rel3/ opt/ floor/ xcheck/`), and the name
   `xcheck/` is used three times for different things (upstream comparison, `pqzh/xcheck/`, `stmt/xcheck.sh`).
5. **Shared crates are not marked as shared**: `stmt/` and `ffi/` serve both systems but look like PQZL siblings.

## 3. Proposed tree

```text
pqz-core/
  README.md  STATUS.md  NOTICE  .gitignore
  pqzl/                      # PQZL, the lattice proof system (C)
    build.sh  check_symbols.sh  check_tbox_fixes.sh
    src/  lazer/  params/  kat/  test/  sv/
    sz/  l2dom/              # tbox-finding PoCs, run by check_tbox_fixes.sh (regression, not spikes any more)
  pqzh/                      # PQZH, the hash-based proof system (Rust)
    ligero/                  # THE backend (unchanged path)
    xcheck/                  # C ↔ Rust statement cross-check (unchanged path)
    stark-backup/            # the Plonky3 STARK crate + runs + sol/ + counts (was the top of pqzh/)
  stmt/                      # pqz-stmt, shared (unchanged path)
  ffi/                       # pqz-ffi, shared (unchanged path)
  bench/                     # measurement harnesses with their runs (experiment code stays)
    rel3/  opt/  floor/  upstream/   # upstream/ = today's xcheck/
  artifact/  glic/  fuzz/    # package, licence scan, fuzzing (unchanged paths)
```

Choices inside the proposal (owner may pick otherwise):

| # | Choice | Proposal | Alternative | Why |
|---|---|---|---|---|
| L1 | Shared crates | keep `stmt/` and `ffi/` at the top | `common/{stmt,ffi}` | zero path changes for the two most-referenced crates (`ffi/` 35 external references, the vectors' `generator` fields, Cargo paths); "shared" is stated in the README map |
| L2 | Harness directory | `bench/` | `research/` | they measure; research notes live in `docs/research/` already |
| L3 | `xcheck/` (upstream) | rename to `bench/upstream/` | keep `bench/xcheck/` | ends the triple use of "xcheck"; costs 1 extra reference group |
| L4 | `sz/`, `l2dom/` | under `pqzl/` | under `bench/` | `check_tbox_fixes.sh` runs them in every gate; they are regression tests now |
| L5 | `sv/` | under `pqzl/` (whole, with runs) | split `sv/` checks (pqzl) from `sv/runs` (bench) | splitting a directory breaks the run files' relative names; keep together |
| L6 | Build output | `pqzl/build/` (follows `build.sh`, which `cd`s to its own directory) | keep `build/` at the top with `B=../build` | one rule: outputs sit next to their script |

## 4. Path references that change

Counted on main `4ab2180` with `git grep` (2026-10-15). "Docs" = Markdown outside `pqz-core/`; "pqz-core docs" =
`pqz-core/**/*.md`; "code" = scripts, Rust, C, Cargo, Docker, JSON and Python inside `pqz-core/` outside `runs/`.

### 4.1 Code and build (functional; must change in the move commit)

83 code files mention a moved path (`grep` of `pqz-core/` minus `lazer/`, generated headers, locks and `runs/`);
most C / Python hits are comments. The functional ones:

| Group | Files | Change |
|---|---|---|
| PQZL scripts that `cd "$(dirname "$0")/.."` (pqz-core root) then use `build/`, `src/`, `test/`, `kat/`, `./build.sh` | `rel3/bench.sh`, `rel3/relfix.sh`, `opt/{asan,bench,prof}.sh`, `sv/{bench,diff,fuzz,rel3,check_sv_fixes}.sh`, `sv/review/review.sh`, `sz/build.sh`, `l2dom/build.sh`, `floor/build.sh`, `kat/build-lazer-dump.sh`, `params/regen.sh`, `params/anon/run_sizing.sh`, `glic/absence.sh`, `xcheck/build-{fork,micro,prof}.sh`, `xcheck/static/build.sh` | the `cd` target becomes `pqzl/` (or `../pqzl` from `bench/`), and the `bench/` scripts name `pqzl/build/…` |
| Top scripts | `build.sh`, `check_symbols.sh`, `check_tbox_fixes.sh` | none inside (they `cd` to their own directory and move with `src/ lazer/ params/ test/ kat/ sz/ l2dom/ sv/`) |
| Relative `#include` of another directory | `ffi/csrc/wasm_ti3.c` (`../../src/…`), `pqzh/xcheck/dump_setup.c` (`../../test/pqz_bench.c`), `sv/review/{dom_trace,sv_fuzz5,z21diff}.c` | depth or target changes (`sv/review` → `pqzl/sv/review` keeps `../../test`, `../../sz`) |
| Runtime file paths | `test/run_wasm.mjs` (`../build/wasm/pqz.wasm`), `floor/run_wasm.mjs` (`../build/floor/kern.wasm`) | `floor/` moves away from `build/`: `../../pqzl/build/floor/` |
| `pqz-ffi` | `ffi/build.rs` (`core = CARGO_MANIFEST_DIR/..`, reads `src/ lazer/ params/`, `../smartcontracts/vectors/pqz`), `ffi/run.sh` (`../check_symbols.sh`) | `core` → `../pqzl`; vectors path `../../smartcontracts` unchanged relative to `ffi/`; `../pqzl/check_symbols.sh` |
| `pqz-stmt` | `stmt/xcheck.sh` (`../build.sh`, `-I../src`, `../build/native/libpqz.a`, `../pqzh/xcheck/dump_setup.c`) | `../pqzl/…` |
| PQZH | `pqzh/xcheck/ligero.sh`, `pqzh/xcheck/run.sh` (`../build.sh`, `-I../src`, `../build/native/libpqz.a`; `run.sh` builds the STARK crate from `pqzh/`) | `../pqzl/…`; `run.sh` → `cd stark-backup`; Cargo paths of `pqzh/ligero` (`../../stmt`) and `ffi` (`../pqzh/ligero`) **unchanged** |
| STARK backup crate | `pqzh/Cargo.toml` (`license-file = "../../LICENSE"`), `pqzh/wasm/Cargo.toml`, `pqzh/runs/wr-probe/Cargo.toml` (`path = "../.."`), `pqzh/pqzh_count.py`, `pqzh/sol/{model,ref}.py` | `license-file` one level deeper (`../../../LICENSE`); the inner relative paths move together |
| Package | `artifact/reproduce.sh` (`cd "$(dirname "$0")/.."`, `build/…`, `test/run_wasm.mjs`, `sv/…`, `rel3/…`, `xcheck/shim`, `xcheck/static`), `artifact/results.py`, `artifact/expected-results.json` (run-file names), `artifact/Dockerfile` (`COPY . /src/pqz-core`), `Dockerfile.dockerignore` (`build/`) | every path rewritten; `.dockerignore` and `.gitignore` gain `pqzl/build/` |
| Ignore files | `pqz-core/.gitignore` (`build/`, `artifact/out/`) | `pqzl/build/` |
| CI | `.github/workflows/ci.yml` | **no PQZ job today** (P6e D12: none for now) — nothing to change |
| Root `scripts/` | none reference pqz-core | — |

### 4.2 Docs (text only; a script can rewrite most)

| Where | References | Notes |
|---|---|---|
| `pqz-core/**/*.md` (README, STATUS, `ffi/`, `artifact/`, `params/`, `sz/`, `xcheck/` READMEs) | ≈ 210 bare relative paths (`src/…`, `sv/…`, `rel3/runs/…`; STATUS 101, README 49, artifact 38, sz 11, ffi 6, params 1, xcheck 1) | rewrite with the mapping table of §5 |
| `docs/research/pqz*.md`, `pqzh*.md` (17 notes) | ≈ 340 bare relative mentions (largest: z21 65, licence inventory 61, SV 34, l2-domain 33, tbox 24) + 17 notes with a `pqz-core/<moved path>` reference | research notes are records: rewrite the `pqz-core/…` prefixed ones, add one line "paths as of `4ab2180`; see the layout map" to the others rather than editing every mention (owner may prefer a full rewrite) |
| `docs/contracts/pq-zether.md` | `pqz-core/{src,params,kat,test,sz,check_tbox_fixes.sh}` | normative spec: rewrite all; `docs_check` must stay 0 errors |
| `docs/decisions.md`, `TODO.md`, `HANDOFF.md`, `docs/superpowers/plans/*.md` (p6-roadmap, p6e, p6-anon, ua5a) | `pqz-core/{params,src,lazer,sv,rel3,build.sh,check_tbox_fixes.sh,floor,test}` | rewrite in decisions / TODO; plans and HANDOFF are dated records (leave, or one note line) |
| `smartcontracts/evm/test/pqzh/{Pqzh.sol,PqzhTest.t.sol,ligero/LigeroTest.t.sol}` | `pqz-core/pqzh/sol/…` (comments) | → `pqz-core/pqzh/stark-backup/sol/…`; `pqzh/ligero` comments unchanged |
| `smartcontracts/vectors/pqz/` (README, `pqz_kat.py`, 15 JSON `generator` fields) | `pqz-core/ffi/…`, "pqz-core test/pqz_keys_kat.c" | `ffi/` does not move: only `pqz_kat.py`'s comment changes; the JSON files stay byte-identical (no vector regeneration) |
| `docs/history/` | historical | never edited |

### 4.3 Run files

`*/runs/*` (856 tracked files in pqz-core) are logs of past runs and name the paths of their day. They are **not edited**; they move with
their directory (`git mv` keeps their history). The README / STATUS tables cite them by their new path.

**Size of the change:** ≈ 40 functional files (scripts, `build.rs`, Cargo / Docker / ignore files, 5 C includes,
2 `.mjs`), ≈ 25 docs outside the research notes, the research notes (17 notes with prefixed references, or ≈ 340 bare mentions for a full rewrite, §4.2), and 743
renames.

## 5. `git mv` plan (history preserved, nothing deleted)

One commit with renames only (so `git log --follow` and `git blame -C` see pure renames), then one commit with the
reference rewrites, then one with docs. From `pqz-core/`:

```sh
mkdir -p pqzl bench pqzh/stark-backup
git mv build.sh check_symbols.sh check_tbox_fixes.sh src lazer params kat test sv sz l2dom pqzl/
git mv rel3 opt floor bench/
git mv xcheck bench/upstream
cd pqzh && git mv Cargo.toml Cargo.lock rust-toolchain.toml .gitignore src tests examples wasm runs sol \
  pqzh_count.py counts.txt stark-backup/ && cd ..
git commit -m "pqz-core layout: renames only"        # step 1
```

| Old | New |
|---|---|
| `build.sh`, `check_symbols.sh`, `check_tbox_fixes.sh`, `src/`, `lazer/`, `params/`, `kat/`, `test/`, `sv/`, `sz/`, `l2dom/` | `pqzl/…` |
| `rel3/`, `opt/`, `floor/` | `bench/rel3/`, `bench/opt/`, `bench/floor/` |
| `xcheck/` | `bench/upstream/` |
| `pqzh/{Cargo.toml,Cargo.lock,rust-toolchain.toml,.gitignore,src,tests,examples,wasm,runs,sol,pqzh_count.py,counts.txt}` | `pqzh/stark-backup/…` |
| `pqzh/ligero/`, `pqzh/xcheck/`, `stmt/`, `ffi/`, `artifact/`, `glic/`, `NOTICE`, `README.md`, `STATUS.md` | unchanged |

Step 2: rewrite §4.1 (scripted `sed` per group, reviewed by hand). Step 3: §4.2 docs. Step 4: verification, all under
`scripts/capped`, one job: `pqzl/build.sh all` + `check_tbox_fixes.sh` + KAT 19/19; `NP=2 NV=2 … bench/rel3/relfix.sh
layout` (proofs_fnv equal to `tx0c`, sizes equal); `pqzl/sv/check_sv_fixes.sh`; `stmt/xcheck.sh layout`;
`pqzh/xcheck/ligero.sh`; `ffi/run.sh layout` and `ffi/vectors/run.sh layout` (`pqz-vectors --check` byte-identical, so
the vectors are untouched); `pqzh/ligero` `cargo test`; the STARK backup `cargo build` (it must still build — a backup
that rots is lost); `artifact/reproduce.sh` quick; `python3 scripts/docs_check.py check` 0 errors.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Merge conflicts with the four branches editing pqz-core (`p6e-a5`, `pqz-artifact2`, `p6-anon-s`, `p6f`) | move only after they merge; git's rename detection carries most later edits, but scripts edited on both sides conflict |
| A script silently resolves a missing path (e.g. `check_symbols.sh` passes when its files are missing, STATUS.md Open 9) | fix Open 9 first or check the scan output counts in step 4 |
| `pqz-ffi`'s `build.rs` reads the C core by relative path: a wrong `core` builds nothing or a stale `OUT_DIR` | `cargo clean` before step 4; compare the self-test hash `ed910a2c…` |
| The STARK backup no longer builds after the move (`license-file`, `path = "../.."`) | step 4 builds it; it is never linked by `pqz-ffi`, so a failure blocks nothing but must be fixed (backup rule) |
| Docker context / `.dockerignore` misses `pqzl/build/` → a huge context or stale binaries in the image | update both ignore files in step 2; quick mode in step 4 |
| P6f's image build uses `pqz-ffi` (branch `p6f`, not on main) | `ffi/` does not move; recheck P6f's build paths when it merges |
| `expected-results.json` names run files | regenerate at the freeze anyway; until then rewrite the names in step 2 |
| Research notes cite old paths | §4.2: one "paths as of" line or a full rewrite; `git log --follow` finds the files |

## 7. Order

1. Merge the open pqz-core branches (`p6e-a5`, `pqz-artifact2`, `p6-anon-s`, `p6f` Tasks 1–9).
2. **Before gate A / B and the freeze**, so the frozen package and `expected-results.json` carry the new paths once.
3. One branch `pqz-layout`: steps 1–4 of §5, review, merge per the P6 mandate.
4. Then the freeze runs on the new tree.

## 8. Old README → new locations

The owner's requirement (2026-10-15): nothing of the previous `pqz-core/README.md` (main `4ab2180`, 92 lines) may be
lost. Every fact, command, link, caveat and number of it, and where it is now. "New README" = `pqz-core/README.md` on
branch `pqz-readme`.

| # | Old README item | Now |
|---|---|---|
| 1 | Title; "The PQ Zether proof engine", link pq-zether.md §8, CTR-PQZ-09 | kept, new README intro |
| 2 | Fork of LaZer at `3330e48` (MIT, IBM), link to the LaZer repo, six layers rewritten | kept, "Two proof systems, one precompile" (table + paragraph) |
| 3 | Prover and verifier run without GMP, MPFR, HEXL, floating point, `malloc`, `abort`, stdio | kept, same section |
| 4 | E-S1 spike (P6d): `R_REG` and a first `R_TX`, native and freestanding wasm32 | kept, "Status and what's next" (History) |
| 5 | Then `R_BURN` (also REFRESH), `R_DS` and `R_DR` (also the auditor), `docs/research/pqz-relations-burn-disclose.md` | kept, History; forms table |
| 6 | P6e added `R_TX0`, `stmt/`, `ffi/`, the frozen vectors `smartcontracts/vectors/pqz/` | kept, History |
| 7 | Every byte layout (statements, objects, both proof formats, precompile input, `OP_SELFTEST`) → pq-zether.md §8.1 link | kept, "Statement forms, ids, limits" |
| 8 | State, numbers, what is open → STATUS.md; write-up `docs/research/pqz-core-e-s1.md` | kept, intro + "Status and what's next" (Open link) + "Further reading" |
| 9 | `lazer/`: subset, pristine copy commit `c91b3ab`, changes in place marked `PQZ:`, licence `lazer/LICENSE` | kept, directory map `lazer/` |
| 10 | `src/`: rewritten layers and C ABI `pqz.h` | kept, map `src/` |
| 11 | `pqz_mpn.h` integers without GMP; incomplete NTT mod q = 2^42 − 215, l = 4 (`pqz_ntt.c`); fixed-point exp (`pqz_fixexp.h`); arena (`pqz_arena.c`); sticky errors (`pqz_rt.h`); bitsliced AES-256-CTR (`pqz_aes_gen.h` from `gen_aes.py`) | kept, "Two proof systems" paragraph + map `src/` |
| 12 | Relations `R_REG`, `R_TX`, `R_TX0` (transfer without auditor, CTR-PQZ-24, op 1 by length), `R_BURN`, `R_DS`, `R_DR` in `pqz_rel.c`; hedged prover masks CTR-PQZ-19 | kept, map `src/`, forms table, "Two proof systems" |
| 13 | KeyGen / Enc / Dec from seeds (`pqz_keys.c`, §4.2); SHAKE256 added to `lazer/shake128.c`; wasm runtime `pqz_wasm_rt.c` | kept, "What PQZ is" + map `src/`, `lazer/` |
| 14 | `params/`: codegen, six specs, headers `pqz_*_params.h`, `regen.sh` (D1), E-S0 / E-S1 sizing (`e_s0.py`, `e_s1_proof.sage`, `estimator*.txt`), `params/README.md` | kept, map `params/` |
| 15 | `kat/`: `lazer_dump.c` (one source, upstream or pqz-core backend), golden `lazer-3330e48.json`, `check.py`, `build-lazer-dump.sh` | kept, map `kat/` |
| 16 | `test/`: `pqz_bench.c` (prove, verify, tamper checks, hedging check, timings, proof hash), `run_wasm.mjs`, `pqz_keys_kat.c` (checked by `pqz_kat.py --c-keys`), `runs/` | kept, map `test/` |
| 17 | `opt/`: P6d-2 `bench.sh` (under capped), `prof.sh` (gprof), `asan.sh`, microbenches, raw results `runs/` (STATUS.md) | kept, map `opt/`; "under capped" = the general rule in "Build, test, run" |
| 18 | `rel3/`: `bench.sh` (build, KAT, `R_REG` / `R_TX` hashes, timings), `relfix.sh` (after the owner's fix-ups: build, KAT, hashes, arena peak per relation, ASan + UBSan, timings), `runs/` | kept, map `rel3/` + "Full measurement rounds" |
| 19 | `sz/`, `l2dom/`: the two tbox fixes behind v2, links lazer#24 / #25, challenge-row trace and pooled-slack cheating prover, `sz/README.md` | kept, map `sz/`, `l2dom/` (+ P6-SZ / P6-L2 names) |
| 20 | `check_tbox_fixes.sh` fails if either fix is gone, or if the z21 norm check (P6-Z21, lazer#26, verifier only, `pqz-z21-norm.md`) is gone | kept, map `check_tbox_fixes.sh` |
| 21 | `glic/`: G-LIC step 1, `absence.sh` (builds into `build/glic`, scans symbols, `DT_NEEDED`, wasm imports, strings), `runs/` | kept, map `glic/` + command |
| 22 | `stmt/`: `pqz-stmt` (P6e Task 5, plan R2 / D15), Rust `no_std` + `alloc`, no deps, wasm32; every form of both systems, `pk` / ciphertext, bundle, opening, precompile input (`MAX_PROOF(id)`, `MAX_INPUT`); `xcheck.sh` content | kept, "Two proof systems" (shared) + map `stmt/` + command |
| 23 | `ffi/`: `pqz-ffi` (P6e Task 7, D10 / R5 / D13), C ABI `pqz_ffi.h`, decode with `pqz-stmt`, dispatch on `proofSystemId` to the specialised verifier (built by `build.rs` with `build.sh`'s flags, one lock, one worker thread, fixed arenas) or the Ligero crate, `OP_SELFTEST`, feature `prove` (wasm32 byte-equal) | kept, "Two proof systems" + map `ffi/` |
| 24 | `ffi/run.sh` (tests, symbol scans, C smoke test, wasm32 diff, bench), `runs/`, `ffi/README.md` | kept, commands + map |
| 25 | `src/bin/pqz-vectors.rs` (P6e Task 11, feature `prove`), `vectors/` (`run.sh`, `tamper.py`, `replay_wasm.mjs`, runs) | kept, map `ffi/` + commands |
| 26 | `artifact/`: source only, pinned `Dockerfile`, `reproduce.sh` (quick, `--full`, `--serve`, `--upstream`), `results.py`, `expected-results.json`, test logs `runs/`, `artifact/README.md` | kept, "Shared" commands paragraph + map |
| 27 | `floor/`: verifier-floor microbenchmarks and cost model, `pqz-verifier-floor.md`, `floor/build.sh run` under capped | kept, map `floor/` |
| 28 | `sv/`: P6-SV (`pqz_sv.c`, `pqz_verify_fast`, `pqz-specialised-verifier.md`), `diff.sh`, `bench.sh`, `fuzz.sh`, `rel3.sh`, `check_sv_fixes.sh`, `runs/`; `review/` reproducers (`review.sh dom | norm | zdiff | fuzz`, `z21diff.c`, never compiled by `build.sh`) | kept, map `sv/` |
| 29 | Build commands (`native`, `native-x86v3`, `wasm`, `SV=0 B=build/wasm-nosv`, `all`) with comments | kept verbatim, "PQZL core (C)" |
| 30 | `check_symbols.sh`: only `memcpy`, `memset`, `__stack_chk_fail` (+ `__stack_pointer`); fails on `malloc`, stdio, libm, GMP, MPFR, `getentropy` | kept verbatim |
| 31 | The 15 run / check commands (`pqz_bench` forms and mask, `opt/bench.sh`, `run_wasm.mjs`, `PQZ_VERIFY=fast`, `pqz_sv_diff`, `kat_dump` + `check.py` 19/19, `check_tbox_fixes.sh`, `review.sh zdiff 1`, `check_sv_fixes.sh`, `pqz_keys_kat 1000`, `pqz_kat.py --c-keys`, `pqz_kat.py --check`) | kept verbatim |
| 32 | `R_TX` arena ≈ 0.30 GB alone, 0.31 GB after `R_REG`, keys built at first use and kept, bench allocates 768 MiB | kept verbatim |
| 33 | Same seeds → same `proofs_fnv` native and wasm across pure implementation changes; bench under capped; `-DPQZ_DEBUG_MALLOC` for ASan / LSan | kept verbatim |
| 34 | Regenerate: `codegen/run.sh`, `regen.sh` (D1), `run_e_s1.sh`, `build-lazer-dump.sh <dir> v4` (v3 = AVX2, docker + network) | kept verbatim, "Regenerate" |
| 35 | All three refuse other commits and run pinned images; codegen takes minutes; headers checked in, regenerated on purpose; v4 needs AVX-512 or Intel SDE (`sde64 -spr …`) | kept verbatim |
| 36 | Licences: `NOTICE`; inventory `pqz-licence-inventory.md`; LaZer MIT (c) 2022-2026 IBM, no patent grant (G-LIC) | kept, "Licences" (G-LIC expanded) |
| 37 | Library objects link no GMP, MPFR, HEXL, libstdc++ | kept, "Licences" (+ the absence-scan file) |
| 38 | `kat/build-lazer-dump.sh` links upstream with GMP / MPFR (LGPL), HEXL, libstdc++; local output, never committed or distributed (LGPL relinking duties) | kept verbatim |
| 39 | Intel SDE 9.48.0 used once locally; not vendored, not needed to build or test | kept verbatim |

**Summary:** 39 items; **39 kept in the new README** (31 verbatim or with the same wording, 8 reorganised into the new
sections), **0 moved out, 0 dropped**. Additional homes that already held the same facts: STATUS.md ("Done", "Optimisation
P6d-2", "R_BURN, R_DS, R_DR", "proofSystemId v2", "z21 norm check", "`pqz-stmt`", "`pqz-ffi`", "Vectors"),
`ffi/README.md`, `artifact/README.md`, `params/README.md`, `sz/README.md`.

## Owner ruling (2026-10-15)

Approved with one change: the measurement / spike directory is `research/` instead of `bench/` (`research/{rel3,opt,floor,upstream}`). Everything else as proposed; executed after `p6e-a5`, `pqz-artifact2`, `p6-anon-s` and `p6f` merge, before gates A / B and the freeze.
