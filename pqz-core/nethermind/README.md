# `Nethermind.Pqz` — the PQZ and ML-DSA precompiles for the SCaaS testnet (P6f)

This folder holds the code that lets a blockchain node check PQZ proofs. It is a **plugin** for the Nethermind 2.2.0
Ethereum client (no change to Nethermind itself) that adds three **precompiles**: built-in contracts at fixed
addresses that run native code instead of EVM bytecode. One of them, `PQZ`, hands each proof to the PQZ library
`libpqz_ffi.so`; the other two check ML-DSA signatures. It runs today on the SCaaS testnet (chain id 7622), which runs
Amsterdam (Glamsterdam) since its reset on 2026-10-21. The SCaaS testnet is a test chain whose data may be reset; the
code is unaudited. What PQZ is and how the library works: the parent [pqz-core README](../README.md), §3
["Two proof systems, one precompile"](../README.md#3-two-proof-systems-one-precompile).

- **Image:** the plugin ships in the local Docker image `scaas/nethermind-pqz:2.2.0-pqz6` (built locally, never
  pushed; live on the SCaaS testnet since 2026-10-31, `sha256:656d91d6…3e83`): Nethermind 2.2.0 + the reviewed library
  `dd0e7668…e5601` (byte-identical to pqz5's; set `n2304-kmax4096`, PQZL v5 `0xef1ffbcb…` / PQZH v3 `0x046859a8…`,
  `pqz_max_input()` 524,288) + the plan 5h Task 8d part 2b plugin (`id_check_head` in `PQZ-START`; the right
  `scaas.pqz.selftest` label `d6c01fbc…`), with the **calibrated** `engine.Pqz` rows (`chain/engine-pqz.json`, plan 5h
  Task 9 / fs3 Task 13, [§ Prices](#prices-calibrated-2026-10-31)). History: `1.39.0-pqz1` (2026-10-16), `1.39.0-pqz2` (2026-10-17, the
  multi-recipient transfer, P6-ANON S8; C PQZL core), `1.39.0-pqz3` (2026-10-19, never ran on the testnet),
  `2.2.0-pqz3` (2026-10-21; library `16dd99ce…` from `1adbd563`), `2.2.0-pqz4` (2026-10-25; library `0894d191…` from
  `54c7c88e`, the plan 5h Task 8d ids PQZL v4 / PQZH v2), `2.2.0-pqz5` (2026-10-26, provisional rows × 1.3),
  `2.2.0-pqz6` (2026-10-31, calibrated rows). The `2.2.0-pqz5` image carries
  pqz4's `scaas.pqz.selftest` label `23d7a1db…` (a Dockerfile literal then; the plugin's own start-up check uses the
  right hash `d6c01fbc…`); since plan 5h Task 8d part 2b `build-image.sh` passes the set's `SelfTest.ExpectedHash`
  as the label and checks it after the build (`2.2.0-pqz6` is the first image built so).
- **Nethermind 2.2.0 (2026-10-21):** the first release with Glamsterdam on Hoodi; 64 KiB contracts (EIP-7954) and
  200 M-gas blocks. What the port changed and what Amsterdam's gas rules mean for our pins (`ROLL_MAX`, op 7 M = 8,
  the precompile gas): [§ Nethermind 2.2.0 and Amsterdam](#nethermind-220-and-amsterdam-2026-10-21) and
  [`runs/2026-10-21-glamsterdam-gas-impact.md`](runs/2026-10-21-glamsterdam-gas-impact.md).
- **Plan:** [P6f](../../docs/superpowers/plans/2026-10-14-p6f-precompiles.md). **Spec:**
  [pq-zero-knowledge.md](../../docs/contracts/pq-zero-knowledge.md) CTR-PQZ-10 / CTR-PQZ-11, §9.1–§9.3, §10.
- **Operating the chain** (roll-out, rollback, health checks): [chain/RUNBOOK.md](chain/RUNBOOK.md).

**Words used here**

| Term | Meaning |
|---|---|
| chainspec | the chain's JSON configuration (`genesis.json` on the chain host); the plugin reads its `engine.Pqz` section |
| `engine.Pqz` | the chainspec section that turns the precompiles on; the plugin is enabled only when it is present |
| schedule | one entry of `engine.Pqz.schedules`: a start timestamp plus the gas prices that apply from then on |
| row | one gas price in a schedule, for one `(op, proofSystemId, statement length)`; rows for the multi-recipient transfer also carry `(M, auditorOn)` |
| miss | an input that matches no row: it pays the smallest row and gets `…00` (invalid) without calling the library |
| multi-recipient transfer | `R_TXM`, op 7: one proof for a transfer to M recipients ([parent README](../README.md)) |
| P/Invoke | the .NET way of calling a C function in a shared library; here `pqz_precompile` in `libpqz_ffi.so` |
| copy | a throwaway replica of the SCaaS testnet used to rehearse every step before it runs on the real chain |

## The three precompiles

The addresses are the 32-bit form (spec 2026-10-20 §12 item 9, plan 5h Task 8d part 1); live on the SCaaS testnet since image
`2.2.0-pqz4` (2026-10-25); the earlier images served P6f D3's `0x5caa500000000000000000000000000000000f01` / `…0012` / `…0013`.
`PQZ`'s input limit (`PqzNative.MaxInput`, an input above it is a failed call) is the loaded library's
`pqz_max_input()`, the `MAX_INPUT` of the parameter set it was built for (524,288 B at the default `n2304-kmax4096`;
was the literal 393,216 of `n2048-kmax1024`).

| Address | Name | What it checks | Gas |
|---|---|---|---|
| `0x000000000000000000000000000000005caa0f01` | `PQZ` | a proof of either proof system (PQZL or PQZH), through `pqz-ffi`'s C function `pqz_precompile` (P/Invoke into `libpqz_ffi.so`) | the active schedule's row `(op, id, stmtLen)` — the multi-recipient transfer (op 7) also `(M, auditorOn)` from header words 320 / 448 — + 3·⌈len/32⌉; a miss = the smallest row (and `…00`, no FFI call); op 6 = `selftestGas` |
| `0x000000000000000000000000000000005caa0012` | `MLDSA44` | an ML-DSA-44 signature; EIP-8355 input layout `pk ‖ sig ‖ msg`, empty context; .NET 10 `MLDsa` (OpenSSL 3.5 of the base image); never reverts: a short input or a `CryptographicException` from .NET is `…00` (review W-R) | `mldsa44Gas` (≥ 6,500; calibrated 49,000) + 6·⌈max(0, L − 3,732)/32⌉ |
| `0x000000000000000000000000000000005caa0013` | `MLDSA65` | the same for ML-DSA-65 | `mldsa65Gas` (≥ 9,000; calibrated 68,000) + 6·⌈max(0, L − 5,261)/32⌉ |

How to read the gas column: `id` is the statement's `proofSystemId`, `stmtLen` its length in bytes and `len` the
length of the whole input, so `PQZ` adds 3 gas per 32-byte input word to the row price. For ML-DSA, `L` is the input
length; 3,732 (ML-DSA-44) and 5,261 (ML-DSA-65) are the public key plus the signature, so the extra charge is 6 gas per
32-byte word of message. The calibrated values are in the results table below.

### How a call reaches the library

A contract calls the `PQZ` address; the plugin prices the input, passes it to `libpqz_ffi.so` and turns the library's
status code into the call's result.

```mermaid
flowchart LR
  C["contract on the SCaaS testnet"] --> VM["Nethermind VM"]
  VM --> PQ["PqzPrecompile (C#)<br/>prices the input from the schedule"]
  PQ -->|"P/Invoke"| FFI["libpqz_ffi.so<br/>pqz_precompile"]
  FFI --> L["PQZL (Rust core pqzl)"]
  FFI --> H["PQZH (Ligero, Rust)"]
  FFI -->|"status 0"| O["32-byte answer<br/>…01 valid / …00 invalid"]
  FFI -->|"status 1: input over MAX_INPUT"| F["failed call, all gas used"]
  FFI -->|"status 3: input caused a panic"| W["…00, log PQZ-INPUT-PANIC"]
  FFI -->|"status 2 (bad arguments) or 4 (fault in the node)"| X["log PQZ-NODE-FAULT,<br/>node exits with code 120"]
```

A node fault never becomes a verdict: the node stops before it seals the block, and a restart re-processes that block
(see the health checks in the [runbook](chain/RUNBOOK.md)).

### How the plugin turns on

The plugin reads `engine.Pqz` from the chainspec. Each schedule's timestamp becomes a fork transition, and from that
timestamp on the three addresses are added to the node's precompile table. A release that Nethermind builds for a
block-number transition (for example `maxCodeSizeTransition`) carries the schedule in force at the genesis timestamp,
and from the first timestamp transition on Nethermind looks releases up by timestamp alone, so a block-number
transition never drops the precompiles (review W-D, 2026-10-19: refuted, the test
`A_block_number_transition_keeps_the_schedule` is the proof). At start-up the plugin checks that its registrations
took effect, that .NET supports ML-DSA and gives the compiled-in known answers (`MlDsaKat`: 8 cases per level through
the precompile path, the verdicts' SHA-256 against a constant; review R4-C4), that the library's SHA-256 equals the
reviewed value of its set compiled into the plugin (`SelfTest.ExpectedLibrarySha256`, review W-G; one per set since the
R0 review fix part b), that the library's self-test (op 6) returns the expected hash and that the schedule in force at
the next block (block-tree head timestamp + 1, the genesis on an empty database) and every later one carry only the
set's proofSystemIds (`PqzSetIds`, generated by `gen_set.py`; review R4-C3, owner 2026-10-26: so after an id switch at
T a new-library node starts once its head reaches T − 1 — in practice after T, see §9.1 — and a fresh node needs a
data copy past T,
`pq-zero-knowledge.md` §9.1); it then logs
`PQZ-START` (library SHA-256, self-test, `max_input`, the OpenSSL version, the ML-DSA KAT hash, the set, addresses,
schedules; since plan 5h Task 8d part 2b, live since `2.2.0-pqz6` (2026-10-31), also the head the id check read:
`id_check_head=<timestamp> (block <n>)`, or `(genesis, empty database)`, `runs/2026-10-26-t8d2b-startup-n2304-kmax4096.txt`;
with a non-zero genesis timestamp 16 both paths log `id_check_head=16`, `runs/2026-10-26-t8d2b-fix-startup-ts16-n2304-kmax4096.txt`.
The runs show the field on an empty database and on one whose head is block 0 only: a head past genesis needs produced
blocks, which these throwaway runs do not have; that branch is covered by the `IdCheckHead` unit test). Any failure logs `PQZ-REFUSE` and the node
exits with code 120 instead of running without the precompiles. On Nethermind 2.x these checks are the init step
`PqzStartupCheck` (after `InitializeBlockTree`, before `LoadGenesisBlock`): 2.x no longer calls a plugin's `Init`.

```mermaid
flowchart LR
  CS["chainspec engine.Pqz (strict)"] --> P["PqzChainSpecEngineParameters"]
  P -->|"AddTransitions: every timestamp (fork id)"| SP["PqzChainSpecBasedSpecProvider"]
  P -->|"ApplyToReleaseSpec: ActiveSchedule (cast fails closed)"| RS["PqzReleaseSpec"]
  RS -->|"BuildPrecompilesCache: + 3 addresses when active"| VM["Nethermind VM"]
  VM --> PP["PqzPrecompileProvider (Ethereum table + 3)"]
  PP --> PQ["PqzPrecompile → pqz_precompile"]
  PP --> ML["MlDsa44 / MlDsa65 → System.Security.Cryptography.MLDsa"]
```

## Layout

The labels in brackets (R1, D1–D6, Task 1–6) point to the decisions and tasks of the
[P6f plan](../../docs/superpowers/plans/2026-10-14-p6f-precompiles.md).

| Path | What |
|---|---|
| `ref.sh` | extracts `/nethermind` of the pinned base image into `ref/` (git-ignored); every project compiles against it (R1) |
| `Nethermind.Pqz/` | the plugin: `PqzPlugin` (enabled only when `engine.Pqz` is present) and its init step `PqzStartupCheck` (start-up checks R3, log tag `PQZ-START`), `PqzChainSpecEngineParameters` (D2), `PqzReleaseSpec`, `PqzChainSpecBasedSpecProvider`, `PqzPrecompileProvider` (D1), `PqzPrecompile` + `Native` (D4, D6), `MlDsaPrecompile` (D5), `MlDsaKat` (R4-C4), `SelfTest` (per-set hashes), `PqzSetIds` (generated by `gen_set.py`, R4-C3), `Addresses` (D3) |
| `Nethermind.Pqz.Test/` | NUnit tests: spec / chainspec (Task 1), every PQZ vector through the C# class and the child processes for status 4 (node fault, Task 2) and status 3 (input panic, review R4-C6), ML-DSA (Task 3) |
| `Harness/` | the harness that stresses the P/Invoke boundary (Task 4) and the child processes of the fault and panic tests |
| `fault-hooks/` | test-only shared library: `pqz-ffi` with `test-hooks` + `pqz_test_fail_worker` and `pqz_test_panic` (never in the image) |
| `fresh-proofs/` | N fresh honest proofs per form (used for calibration only) |
| `Calibrate/` | the gas calibration (Task 6), run inside the image's `calib` target |
| `corpus.py` | builds the flat input corpus from the parameter set's vectors (`PQZ_SET`, default `n2304-kmax4096` = `pqz-ffi`'s default build: `smartcontracts/vectors/pqz/n2304-kmax4096/`) into `bin/corpus.jsonl` for every consumer (`e2e.py`, `probe.sh`, `provisional-rows.py`, the C# tests, the harness, the calibration). `bin/` is git-ignored, so the file is generated: **regenerate it after every parameter-set or library change** (`PQZ_SET=n2304-kmax4096 python3 -I pqz-core/nethermind/corpus.py pqz-core/nethermind/bin/corpus.jsonl` from the repo root; `n2304-kmax4096` today: 877 inputs, 51 valid = 43 honest + 8 fee0, self-test `d6c01fbc…`, PQZL `ef1ffbcb…`, PQZH `046859a8…`). A stale corpus carries retired proof-system ids and the old self-test hash: `e2e.py probe` / `burst` then fail against the live node (regenerated 2026-10-31; the 2026-10-15 file of 414 rows is kept as `bin/corpus.jsonl.bak-20261015` in the main checkout) |
| `Directory.Build.props`, `run-tests.sh`, `harness.sh`, `calibrate.sh` | the `PqzSet` MSBuild property (default `n2304-kmax4096`), the test, harness and calibration runs |
| `Dockerfile`, `Dockerfile.dockerignore`, `build-image.sh`, `NOTICE-pqz.txt` | the image (Task 5) |
| `chain/` | the copy and the live runbook: `copy.sh`, `docker-compose.copy.yml`, `config.{signer,follower}.json`, `nginx-rpc.conf`, `patch-chainspec.py`, `add-schedule.py`, `probe.sh`, `e2e.py`, `eth.py`, `watch.sh`; `engine-pqz-provisional-<n>.json` (provisional rows per set, made by `provisional-rows.py`) and `engine-pqz.json` (the retired calibration of 2026-10-15 / 17, PQZL v3 / PQZH v1 ids, refused at start-up by today's plugin) |
| `runs/` | every run's output (text) |

## Build and test

Run every command from the repository root. Heavy jobs go through `scripts/capped`, the repository's machine lock
(two jobs at a time). After a `dotnet` job, `dotnet build-server shutdown` releases the compiler server that would
otherwise keep holding the lock.

```sh
# 1. Extract the pinned Nethermind reference and build the input corpus
scripts/capped sh -c 'pqz-core/nethermind/ref.sh && python3 -I pqz-core/nethermind/corpus.py pqz-core/nethermind/bin/corpus.jsonl'
# 2. Build the pqz-ffi shared library the tests load (default features: the set n2304-kmax4096, the corpus' set)
scripts/capped sh -c 'cd pqz-core/ffi && cargo build --release --offline'                     # cdylib for the tests
# 3. Build the test-only fault-hook library
scripts/capped sh -c 'cd pqz-core/nethermind/fault-hooks && cargo build --release --offline && mkdir -p ../bin/test-hooks && cp target/release/libpqz_ffi_fault_hooks.so ../bin/test-hooks/libpqz_ffi.so'
# 4. Run the NUnit tests
scripts/capped sh -c 'cd pqz-core/nethermind && dotnet test Nethermind.Pqz.Test -c Release -m:2'; dotnet build-server shutdown
# 5. Run the P/Invoke harness for 60 minutes on the host ...
scripts/capped sh -c 'cd pqz-core/nethermind && dotnet Harness/bin/Release/net10.0/Harness.dll run ../ffi/target/release bin/corpus.jsonl ../.. --minutes 60'
#    ... or the same inside the base image's .NET runtime
scripts/capped pqz-core/nethermind/harness.sh 60 1h                                         # the same, in the base image's runtime
# 6. Build the image (with CALIB=1 also the calib target)
CALIB=1 scripts/capped pqz-core/nethermind/build-image.sh pqz1                               # runs/<date>-image-pqz1.txt (+ calib target)
#    ... the image live on the SCaaS testnet since 2026-10-31 (library byte-identical to pqz5's, plugin of plan 5h Task 8d part 2b)
CALIB=1 scripts/capped pqz-core/nethermind/build-image.sh pqz6   # 2.2.0-pqz6 + -calib (runs/2026-10-30-image-pqz6.txt)
# 7. Calibrate the gas prices on the chain host (2026-10-31: two runs in slices, runs/2026-10-30-fs3-t13-calib-step.sh, then
#    runs/2026-10-31-fs3-t13-rows-one-baseline.py: the rows of chain/engine-pqz.json; see § Prices)
scripts/capped pqz-core/nethermind/calibrate.sh pqz1                                       # ONE run: runs/<date>-calib.txt, chain/engine-pqz.json
```

**Another parameter set (plan 5h Task 8d part 1b).** The plugin is built for the set of the library it loads: the
MSBuild property `PqzSet` (`Directory.Build.props`, default `n2304-kmax4096`) selects `SelfTest.ExpectedHash` (the
set's `selftest.json` hash) and an unknown set does not compile. The tests of another set, e.g. `n2816-kmax65536`
(PQZL only): build its library (`cd pqz-core/ffi && CARGO_TARGET_DIR=target/neth-<set> cargo build --release --offline
--no-default-features --features pqzl-rust,set-<set>`), its fault-hook library (`cd fault-hooks && cargo build --release
--offline --no-default-features --features pqz-ffi/set-<set>`, copied to a directory of its own as `libpqz_ffi.so`) and
its corpus (`PQZ_SET=<set> corpus.py bin/corpus-<set>.jsonl`), then `PQZ_SET=<set> PQZ_FFI_DIR=<abs dir> PQZ_CORPUS=<abs
file> PQZ_HOOKS_DIR=<abs dir> scripts/capped pqz-core/nethermind/run-tests.sh` (log `runs/<date>-test-<set>.txt`; the
script passes `-p:PqzSet=$PQZ_SET`). `SelfTest.ExpectedLibrarySha256` holds each set's reviewed library (the
Dockerfile's `ffi` stage with `--build-arg PQZ_SET=<set>`, logs `runs/2026-10-26-r01b-ffi-<set>.txt`; R0 review fix part
b), and `PQZ_SET=<set> build-image.sh <label>` builds that set's library, plugin and image (the `calib` target and
`fresh-proofs`, which iterates both ids, stay the default set's). Provisional testnet rows per set:
`chain/engine-pqz-provisional-<n>.json` (`n2048` / `n2304` / `n2560` / `n2816`, the R0 fix ids; the SCaaS testnet's live
`2.2.0-pqz5` ran `engine-pqz-provisional-n2304.json` 2026-10-26 to 2026-10-31; `2.2.0-pqz6` runs the calibrated `engine-pqz.json`).

**The reviewed library (review W-G, 2026-10-19).** `build-image.sh` reads `ExpectedLibrarySha256` from
`Nethermind.Pqz/SelfTest.cs`, builds `libpqz_ffi.so` (the `ffi-export` target) and stops with `FAIL the built library is
not the reviewed one` unless the two hashes are equal; the Dockerfile checks the library in the image against the same
value and the plugin refuses to start with any other library. A change to the library is therefore: build, review the
new hash (the failure line prints it), set it in `SelfTest.cs`, commit, build again (the `ffi` stage comes from the
cache). Since the R0 review fix part b `SelfTest.cs` holds one reviewed hash per set; at `n2304-kmax4096` it is
`dd0e7668…e5601`, the library of `2.2.0-pqz5` and `2.2.0-pqz6`. `clang` in the Dockerfile is pinned to exact Debian 12 package versions.

The commands show the first image label, `pqz1`; the live image is `pqz6` (above). History: the multi-recipient
calibration of 2026-10-17 was `calibrate.sh pqz2 --ops 7`: it writes only the op 7 rows
(`runs/2026-10-17-calib-ops7*`) and leaves `chain/engine-pqz.json` unchanged, because those rows join the live rows in
a second schedule.

**`FFI_REV` (2026-10-21; `2.2.0-pqz5` was built the same way, `FFI_REV=349b96b8`).** On main the library sources moved on after the reviewed build (pqzl-fs3 Task 5: the PQZL
`proofSystemId` v3 and regenerated vectors; A-3 secret wiping), so a build from the work tree gives `ee2f7096…`, not
the reviewed `16dd99ce…`, and `build-image.sh` stops (`runs/2026-10-21-image-pqz3-failed-main-ffi.txt`). With
`FFI_REV=<commit>` the script extracts that commit's tree (`git archive` into `bin/ffi-src`) and passes it as the
Dockerfile's `ffisrc` build context, so the library is built (reproducibly, the same sha256) from the reviewed commit
while the plugin comes from the work tree. A library change is still the review step above; `FFI_REV` does not replace
it. The probe and e2e of such an image use that commit's vectors: `python3 -I bin/ffi-src/pqz-core/nethermind/corpus.py
bin/corpus-ffi-<rev>.jsonl` and `e2e.py … --corpus bin/corpus-ffi-<rev>.jsonl`.

## Nethermind 2.2.0 and Amsterdam (2026-10-21)

**Port** (commits on branch `nethermind-2.2`): base `nethermind/nethermind:2.2.0@sha256:5cc0061e…`, SDK
`10.0.402-resolute@sha256:6924c5c6…` (2.2.0's build SDK; its runtime is .NET 10.0.13 with OpenSSL 3.5.5, as the base
image). Changes Nethermind 2.x forced:

| Nethermind 2.x | Plugin change |
|---|---|
| `IPrecompile.BaseGasCost` / `DataGasCost` and the spec provider's block numbers are `ulong` (2.0.0: numeric API types) | gas returns `ulong`; no schedule ⇒ `ulong.MaxValue` (out of gas, as before) |
| `ReleaseSpec` indexes precompiles by number and throws for an address with a non-zero byte above its low 32 bits ("a precompile number must fit 32 bits") | `PqzReleaseSpec` re-implements `IReleaseSpec.Precompiles` / `IsPrecompile` over its own set; every caller in Nethermind goes through the interface, and the code-info repositories fall back to the provider's dictionary for a number they cannot index. Test `IsPrecompile_finds_the_three_from_T` |
| The plugin `Init` hook is gone (init steps, #12326): `Init` still compiled and was never called | `PqzStartupCheck` step; test `Startup_checks_are_a_step_before_genesis` (the first `2.2.0-pqz3` build ran a few minutes without `PQZ-START` before this was found, see the run log) |
| `IJsonSerializer.Deserialize<T>` returns `T?` | `!` in the harness, calibration and tests |

Tests 46 / 46 in the pinned SDK image (`runs/2026-10-21-test.txt`). Not re-run for this port: the 60-minute P/Invoke
harness (the boundary and the library are unchanged) and the calibration (owner's go).

**Amsterdam on the SCaaS testnet.** Reset on 2026-10-21 (owner: reset directly, no backup), `eip<N>TransitionTimestamp`
= 1 for EIP-2780, 7708, 7778, 7928, 7954, 7976, 7981, 8024, 8037, 8038, 8246 — Amsterdam from block 1, the genesis
block (and hash `0x24e43dcb…c464`) unchanged. Not enabled: EIP-7843 (SLOTNUM needs a consensus layer's slot number;
the Clique producer sets none and 2.2.0 rejects such a header) and EIP-8282 (builder requests: CL predeploys). Code
size 64 KiB native (EIP-7954; `maxCodeSize` 0x10000 stays for the genesis release). `Blocks.TargetBlockGasLimit`
80 M → 200 M: a 64 KiB deploy is ≈ 100 M of EIP-8037 state gas and needs a block larger than its `tx.gas`.
History (2026-10-21): `engine.Pqz` kept the two schedules the testnet ran before (PQZL rows with the v2 id
`0x2e07e6ed…`, which the reviewed `pqz3` library verifies; copy in `runs/2026-10-21-testnet-engine-pqz.json`). **The v2
id is the forgeable one**: the PQZL v2 transcript lets a proof be forged (fixed by v3 / `0x8079d65b…`, pqzl-fs3 Task
5), so a PQZL proof accepted by the testnet then proved nothing — a test chain only (owner ruling, review
nethermind-2.2 M5). The `2.2.0-pqz4` reset (2026-10-25) replaced those rows with the plan 5h Task 8d ids, the
`2.2.0-pqz5` reset (2026-10-26) with PQZL v5 / PQZH v3 ([RUNBOOK](chain/RUNBOOK.md)). Procedure:
[chain/RUNBOOK.md](chain/RUNBOOK.md#nethermind-220-and-amsterdam-on-the-scaas-testnet-executed-2026-10-21); log
`runs/2026-10-21-testnet-2.2.0.txt`.

**Gas-rule headline** ([full report](runs/2026-10-21-glamsterdam-gas-impact.md)): (1) the EIP-7976 calldata floor (64
gas per byte) must stay under 2^24 (EIP-8037), so **no transaction carries more than ≈ 261,909 calldata bytes**:
every PQZH TRANSFER / BURN / REFRESH / op 7 input and PQZL op 7 M = 8 with the auditor are now refused when the precompile
input is the transaction's calldata (measured, probe / e2e of 2026-10-21), and the op 7 M = 8 input of `n2560-kmax16384` at its plan 5h
Task 7 sizes (309,591 B) can never be calldata; (2) EIP-8038's 10,000-gas storage write puts that set's `ROLL_MAX` =
192 rollover at ≈ 16.6–18.0 M, so `ROLL_MAX` under 0.75 · 2^24 becomes ≈ 80–96 [estimate; measured since plan 5h Task
8d part 2b: 96 / 80 / 64 / 32 at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`, the
sets' `set.toml` `roll_max`, on both relay paths]; (3) the precompile prices are unchanged (every probed row = formula); (4) every SSTORE2
op blob becomes ≈ 26–32 M of state gas. Through the token the precompile input is built in memory, so only the call's
calldata counts: the measured gas per relation and set is in
[`../params/sets/README.md`](../params/sets/README.md#one-transactions-gas-per-relation-measured-plan-5h-task-8d-part-2b).

**Prepared for the next reset (2026-10-22, branch `amsterdam-node`; the review nethermind-2.2 minors that need no new
library).** (a) `chain/patch-chainspec.py --testnet-reset` sets the genesis `gasLimit` to 200,000,000 (`0xbebc200`,
= `TargetBlockGasLimit`: no 2.5 h ramp) and replaces an existing `engine.Pqz` (reset only); the genesis hash changes
with it. Checked on a throwaway chain (`runs/2026-10-22-genesis-200m-throwaway.txt`): block 0 `gasLimit` 200 M, a
65,536 B contract deployed in block 9 (100,504,388 gas), 65,537 B refused, a 22.0 M-gas transaction (200 new slots,
regular < 2^24) included, probe all checks passed; the live genesis through the same reset gives the hash
`0xa17faef4…2ac2`. **The SCaaS testnet was reset with it on 2026-10-22** (script
`runs/2026-10-22-testnet-reset-200m.sh`, log `runs/2026-10-22-testnet-200m.txt`): genesis `0xa17faef4…2ac2` as predicted,
block 1 `0xca1fbc04…f012`, image `sha256:b3f6c855…`, `gasLimit` 200 M from block 0, probe / e2e / `codesize` all
checks passed ([RUNBOOK](chain/RUNBOOK.md#genesis-gaslimit-200-m-on-the-scaas-testnet-executed-2026-10-22)). (b) `e2e.py probe`
has an `eth_estimateGas` row (a direct call to `PQZ` estimates the precompile row: 3,394,851 vs exact 3,366,962,
+0.8 %, on the throwaway chain), closing the review's open point on Facade / JsonRpc. (c) Fail-closed drill (M1) on a
throwaway container: a library with one appended byte gives `PQZ-REFUSE … != the reviewed 16dd99ce…` and exit 120
3.5 s after start, RPC never answered; the untampered control starts (`runs/2026-10-22-fail-closed-drill.txt`).
(d) M4 (no `.dockerignore` for the default build) does not hold: BuildKit reads `Dockerfile.dockerignore` (an
allowlist) for `-f Dockerfile`; the default build sends 16 MB (`runs/2026-10-22-default-context-check.txt`). (e)
`e2e.py burst` / `fill` pick the largest input under the calldata floor and size `tx.gas` by `intrinsic()` (M2; not
run: Task 13 drills). Not done (owner's go): the 200 M block load rehearsal (M3), timing / gas calibration.

<a id="prices-calibrated-2026-10-31"></a>
## Prices (calibrated 2026-10-31)

`chain/engine-pqz.json` = `runs/2026-10-31-fs3-t13-rows-one-baseline-engine-pqz.json`, live on the SCaaS testnet since
2026-10-31 (image `2.2.0-pqz6`). Rule (owner 2026-10-31, option (b)): every row from its logged `t_row` (max of the
valid and adversarial p99, two calibration runs) at one ecMul baseline `t_ecMul` = 0.016 ms, `gas = 1000·⌈6000·t_row /
0.016 / 1000⌉`, then `min(provisional, max(run 1, run 2))`; `selftestGas` = the smallest row; ML-DSA unchanged. Gas of a
call = row + 3 per input word. Record: `runs/2026-10-31-fs3-t13-rows-one-baseline.md`.

| op | system | stmtLen | M | auditor | provisional (× 1.3, pqz5) | calibrated (pqz6) | change |
|---|---|---|---|---|---|---|---|
| 1 | PQZH | 74,752 |  |  | 5,227,000 | 4,530,000 | -13.3 % |
| 1 | PQZH | 93,312 |  |  | 5,492,000 | 4,634,000 | -15.6 % |
| 1 | PQZL | 74,752 |  |  | 6,790,000 | 3,088,000 | -54.5 % |
| 1 | PQZL | 93,312 |  |  | 7,032,000 | 3,149,000 | -55.2 % |
| 2 | PQZH | 56,192 |  |  | 4,859,000 | 4,392,000 | -9.6 % |
| 2 | PQZL | 56,192 |  |  | 4,840,000 | 3,109,000 | -35.8 % |
| 3 | PQZH | 18,528 |  |  | 4,319,000 | 3,314,000 | -23.3 % |
| 3 | PQZL | 18,528 |  |  | 3,504,000 | 1,721,000 | -50.9 % |
| 4 | PQZH | 37,280 |  |  | 4,268,000 | 3,409,000 | -20.1 % |
| 4 | PQZL | 37,280 |  |  | 3,381,000 | 1,839,000 | -45.6 % |
| 5 | PQZH | 37,280 |  |  | 3,745,000 | 3,392,000 | -9.4 % |
| 5 | PQZL | 37,280 |  |  | 3,337,000 | 1,851,000 | -44.5 % |
| 7 | PQZH | 74,752 | 1 | off | 5,608,000 | 4,485,000 | -20.0 % |
| 7 | PQZH | 93,312 | 1 | on | 5,023,000 | 4,669,000 | -7.0 % |
| 7 | PQZH | 93,312 | 2 | off | 5,740,000 | 4,569,000 | -20.4 % |
| 7 | PQZH | 112,000 | 2 | on | 5,201,000 | 4,865,000 | -6.5 % |
| 7 | PQZH | 130,432 | 4 | off | 6,360,000 | 4,857,000 | -23.6 % |
| 7 | PQZH | 167,808 | 4 | on | 6,416,000 | 6,159,000 | -4.0 % |
| 7 | PQZL | 74,752 | 1 | off | 5,139,000 | 3,158,000 | -38.5 % |
| 7 | PQZL | 93,312 | 1 | on | 4,712,000 | 3,205,000 | -32.0 % |
| 7 | PQZL | 93,312 | 2 | off | 4,975,000 | 3,196,000 | -35.8 % |
| 7 | PQZL | 112,000 | 2 | on | 4,823,000 | 3,204,000 | -33.6 % |
| 7 | PQZL | 130,432 | 4 | off | 5,164,000 | 3,282,000 | -36.4 % |
| 7 | PQZL | 167,808 | 4 | on | 5,357,000 | 4,891,000 | -8.7 % |
| 7 | PQZL | 223,104 | 8 | off | 6,941,000 | 4,709,000 | -32.2 % |
| 7 | PQZL | 260,992 | 8 | on | 8,030,000 | 6,242,000 | -22.3 % |
| 6 (`OP_SELFTEST`) | — | — | | | 3,337,000 | 1,721,000 | -48.4 % |

ML-DSA-44 / -65: 49,000 / 68,000 + 6 per message word (unchanged).

## Runbook

[chain/RUNBOOK.md](chain/RUNBOOK.md) has every step, in order, for:

- **the copy** (Tasks 7–8): the rehearsal on a replica of the SCaaS testnet. Executed; the gate passed on 2026-10-16, with
  the checklist in `runs/2026-10-15-rehearsal.txt`;
- **the live roll-out on the SCaaS testnet** (Task 10): back up, then reset the chain with `engine.Pqz` active from block 0
  (owner decision 2026-10-15). Executed on 2026-10-16, log `runs/2026-10-16-live.txt`;
- **adding the multi-recipient transfer (op 7)** to the running chain with a second schedule. Executed on 2026-10-17,
  log `runs/2026-10-17-s8-live.txt`.
- **Genesis gasLimit 200 M**: the SCaaS testnet reset again with a 200 M genesis block, everything else unchanged.
  Executed on 2026-10-22, log `runs/2026-10-22-testnet-200m.txt`.
- **Nethermind 2.2.0 + Amsterdam**: the SCaaS testnet reset onto `2.2.0-pqz3` with Amsterdam from block 1. Executed on
  2026-10-21, log `runs/2026-10-21-testnet-2.2.0.txt`.
- **Image `2.2.0-pqz4`**: reset (path B, no backup) onto the plan 5h Task 8d part 1 library at `n2304-kmax4096` with
  provisional rows. Executed on 2026-10-25, log `runs/2026-10-25-pqz4-live.txt`.
- **Image `2.2.0-pqz5`**: reset (path B, no backup) onto the R0 review fix part b library (PQZL v5 / PQZH v3) with
  provisional rows. Executed on 2026-10-26, log `runs/2026-10-26-pqz5-live.txt`.
- **Image `2.2.0-pqz6`** (fs3 Task 13 + plan 5h Task 9): reset (path B, backed up) with the calibrated rows, the CREATE2
  deployer in the genesis alloc and EIP-7702 off; the contracts redeployed; the node hardened; Blockscout on. Executed on
  2026-10-31, log `runs/2026-10-31-pqz6-live.txt`; layout and access in RUNBOOK § 7622 node layout and access.

## Results (2026-10-15 to 2026-10-31)

| Task | Result | Log |
|---|---|---|
| 1–3 tests | 36 / 36 in the pinned SDK image | `runs/2026-10-15-test.txt` |
| 4 harness | 1 h clean: 6,955,371 inputs, 8 threads + GC pressure, status 3 = 0, `…01` = honest inputs | `runs/2026-10-15-harness-1h.txt` |
| 5 image | `pqz1` = `sha256:c53359a69bfa…`, library `12495e8b…7d87`, no hooks / GMP / MPFR / HEXL, never pushed | `runs/2026-10-15-image-pqz1.txt` |
| 6 calibration | `t_ecMul` 17 µs; rows 2.567–5.409 M gas; `selftestGas` 2,567,000; ML-DSA 49,000 / 68,000 | `runs/2026-10-15-calib.txt` |
| 7 copy | the stock image ignores `engine.Pqz`; path A before / after T, probe 111, e2e 53; path B probe 112, e2e 53 | `runs/2026-10-1[56]-copy-*.txt` |
| 8 rehearsal | burst 429s, 80 M ramp + full block (79.24 M gas), kill drill, rollback | `runs/2026-10-15-rehearsal.txt` |
| 10 live roll-out | the SCaaS testnet backed up and reset with `engine.Pqz` from block 0 (image `pqz1`); genesis hash unchanged; probe and e2e passed | `runs/2026-10-16-live.txt` |
| S8 multi-recipient transfer (op 7, P6-ANON) | plugin rows per `(id, M, auditorOn)` (plan D19), 41 / 41 tests; harness 60 min CLEAN (4,577,772 inputs); image `pqz2` (library `4fc1a6a2…`); multi-recipient calibration 14 rows 3,625,000–6,177,000 gas; copy path A (pqz1 → pqz2, data kept) before / after T, e2e 86 ok; **live on the SCaaS testnet** 2026-10-17: second schedule at T = 1792205116, probe 389 ok before and after T, e2e 76 ok | `runs/2026-10-17-*` |
| Nethermind 2.2.0 + Amsterdam | port tests 46 / 46; image `2.2.0-pqz3` (library `16dd99ce…` from `1adbd563`); **SCaaS testnet reset** 2026-10-21 with Amsterdam from block 1: `PQZ-START`, genesis hash unchanged, probe all checks passed (input refusals over the floor included), e2e 76 ok, one ordinary transfer; the 64 KiB deploy check waited for the gas-limit ramp and passed after the 200 M genesis reset of 2026-10-22 (RUNBOOK) | `runs/2026-10-21-*` |
| Image `2.2.0-pqz4` (plan 5h Task 8d part 1) | image `sha256:55037b0b…`, library `0894d191…`, set `n2304-kmax4096`, 26 provisional rows; SCaaS testnet reset on path B 2026-10-25; probe 398 ok / 0 FAIL | `runs/2026-10-25-*` |
| Image `2.2.0-pqz5` (R0 review fix part b) | tests 49 / 49 at `n2304-kmax4096` and `n2816-kmax65536`; image `sha256:4d906b55…`, library `dd0e7668…`, PQZL v5 / PQZH v3; SCaaS testnet reset on path B 2026-10-26: `PQZ-START`, genesis hash `0xa17faef4…2ac2` unchanged, probe 420 ok / 0 FAIL, e2e 84 ok / 0 FAIL | `runs/2026-10-26-r01b-*`, `runs/2026-10-26-*pqz5*` |
| plan 5h Task 8d part 2b (not in an image yet) | tests 51 / 51 at `n2304-kmax4096` and `n2816-kmax65536` (the input-panic child process and `IdCheckHead` added); start-up runs with the `id_check_head` field on an empty and on an initialised database (head block 0; with genesis timestamp 0 and 16; no head past genesis); `docker build --check` of the Dockerfile: no warnings | `runs/2026-10-26-t8d2b-*` |
| Image `2.2.0-pqz6` + calibration (fs3 Task 13, plan 5h Task 9) | image `sha256:656d91d6…`, library `dd0e7668…` (= pqz5's), plugin `bf38997a…`; two calibration runs, rows from one ecMul baseline 0.016 ms (option (b)), 26 rows −4…−55 % against the provisional rows, 0 above them, `selftestGas` 1,721,000; native p99 ≤ 16.6 ms (60 ms limit); SCaaS testnet reset on path B 2026-10-31 (genesis `0xf1f491ab…3164`): `PQZ-START` 26 rows, probe 420 ok / 0 FAIL, node e2e 84 ok / 0 FAIL, type-4 refused (`InvalidTxType`), PQZ contract e2e full 254 ok (2 stale list checks, fixed) / `--split` 265 ok / via the hardened public RPC 256 ok, 0 FAIL; `Deploy.s.sol` 31 txs (MtxRelayFee, DEX release) | `runs/2026-10-3[01]-*fs3-t13*`, `runs/2026-10-31-pqz6-live.txt` |

In this table, "path A" and "path B" are the two ways to switch the precompiles on (a future timestamp, or from
genesis; see the [runbook](chain/RUNBOOK.md)); "probe" and "e2e" count the checks that passed in `chain/probe.sh` (read-only
calls: chain id, genesis hash, self-test, every test vector and its gas) and `e2e.py e2e` (real transactions).
