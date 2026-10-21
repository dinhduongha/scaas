# `Nethermind.Pqz` — the PQZ and ML-DSA precompiles for the SCaaS testnet (P6f)

This folder holds the code that lets a blockchain node check PQZ proofs. It is a **plugin** for the Nethermind 2.2.0
Ethereum client (no change to Nethermind itself) that adds three **precompiles**: built-in contracts at fixed
addresses that run native code instead of EVM bytecode. One of them, `PQZ`, hands each proof to the PQZ library
`libpqz_ffi.so`; the other two check ML-DSA signatures. It runs today on the SCaaS testnet (chain id 7622), which runs
Amsterdam (Glamsterdam) since its reset on 2026-10-21. What PQZ is and
how the library works: the parent [pqz-core README](../README.md), §3
["Two proof systems, one precompile"](../README.md#3-two-proof-systems-one-precompile).

- **Image:** the plugin ships in the local Docker image `scaas/nethermind-pqz:2.2.0-pqz3` (built locally, never
  pushed): Nethermind 2.2.0 + the reviewed library of `pqz3` (`16dd99ce…`, the Rust PQZL core, built from commit
  `1adbd563` with `FFI_REV`, see below). History: `1.39.0-pqz1` (2026-10-16), `1.39.0-pqz2` (2026-10-17, the
  multi-recipient transfer, P6-ANON S8; C PQZL core), `1.39.0-pqz3` (2026-10-19, never ran on the testnet),
  `2.2.0-pqz3` (2026-10-21).
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

| Address | Name | What it checks | Gas |
|---|---|---|---|
| `0x5caa500000000000000000000000000000000f01` | `PQZ` | a proof of either proof system (PQZL or PQZH), through `pqz-ffi`'s C function `pqz_precompile` (P/Invoke into `libpqz_ffi.so`) | the active schedule's row `(op, id, stmtLen)` — the multi-recipient transfer (op 7) also `(M, auditorOn)` from header words 320 / 448 — + 3·⌈len/32⌉; a miss = the smallest row (and `…00`, no FFI call); op 6 = `selftestGas` |
| `0x5caa500000000000000000000000000000000012` | `MLDSA44` | an ML-DSA-44 signature; EIP-8355 input layout `pk ‖ sig ‖ msg`, empty context; .NET 10 `MLDsa` (OpenSSL 3.5 of the base image); never reverts: a short input or a `CryptographicException` from .NET is `…00` (review W-R) | `mldsa44Gas` (≥ 6,500; calibrated 49,000) + 6·⌈max(0, L − 3,732)/32⌉ |
| `0x5caa500000000000000000000000000000000013` | `MLDSA65` | the same for ML-DSA-65 | `mldsa65Gas` (≥ 9,000; calibrated 68,000) + 6·⌈max(0, L − 5,261)/32⌉ |

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
took effect, that .NET supports ML-DSA, that the library's SHA-256 equals the reviewed value compiled into the plugin
(`SelfTest.ExpectedLibrarySha256`, review W-G) and that the library's self-test (op 6) returns the expected hash; it
then logs `PQZ-START` (library SHA-256, self-test, schedules, addresses). Any failure logs `PQZ-REFUSE` and the node
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
| `Nethermind.Pqz/` | the plugin: `PqzPlugin` (enabled only when `engine.Pqz` is present; start-up checks R3, log tag `PQZ-START`), `PqzChainSpecEngineParameters` (D2), `PqzReleaseSpec`, `PqzChainSpecBasedSpecProvider`, `PqzPrecompileProvider` (D1), `PqzPrecompile` + `Native` (D4, D6), `MlDsaPrecompile` (D5), `SelfTest`, `Addresses` (D3) |
| `Nethermind.Pqz.Test/` | NUnit tests: spec / chainspec (Task 1), every PQZ vector through the C# class and the status-4 child process (Task 2), ML-DSA (Task 3) |
| `Harness/` | the harness that stresses the P/Invoke boundary (Task 4) and the child process used for the fault test |
| `fault-hooks/` | test-only shared library: `pqz-ffi` with `test-hooks` + `pqz_test_fail_worker` (never in the image) |
| `fresh-proofs/` | N fresh honest proofs per form (used for calibration only) |
| `Calibrate/` | the gas calibration (Task 6), run inside the image's `calib` target |
| `corpus.py` | builds the flat input corpus from `smartcontracts/vectors/pqz` (`bin/corpus.jsonl`) for every consumer |
| `Dockerfile`, `Dockerfile.dockerignore`, `build-image.sh`, `NOTICE-pqz.txt` | the image (Task 5) |
| `chain/` | the copy and the live runbook: `copy.sh`, `docker-compose.copy.yml`, `config.{signer,follower}.json`, `nginx-rpc.conf`, `patch-chainspec.py`, `probe.sh`, `e2e.py`, `watch.sh`, `engine-pqz.json` |
| `runs/` | every run's output (text) |

## Build and test

Run every command from the repository root. Heavy jobs go through `scripts/capped`, the repository's machine lock
(two jobs at a time). After a `dotnet` job, `dotnet build-server shutdown` releases the compiler server that would
otherwise keep holding the lock.

```sh
# 1. Extract the pinned Nethermind reference and build the input corpus
scripts/capped sh -c 'pqz-core/nethermind/ref.sh && python3 -I pqz-core/nethermind/corpus.py pqz-core/nethermind/bin/corpus.jsonl'
# 2. Build the pqz-ffi shared library the tests load
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
#    ... the 2.2.0 image of 2026-10-21: the reviewed library from its own commit, the plugin from the work tree
FFI_REV=1adbd56318b3d07af76d8f61ffbbb27b4b4fd2b0 scripts/capped pqz-core/nethermind/build-image.sh pqz3   # 2.2.0-pqz3
# 7. Calibrate the gas prices, once, on the chain host
scripts/capped pqz-core/nethermind/calibrate.sh pqz1                                       # ONE run: runs/<date>-calib.txt, chain/engine-pqz.json
```

**The reviewed library (review W-G, 2026-10-19).** `build-image.sh` reads `ExpectedLibrarySha256` from
`Nethermind.Pqz/SelfTest.cs`, builds `libpqz_ffi.so` (the `ffi-export` target) and stops with `FAIL the built library is
not the reviewed one` unless the two hashes are equal; the Dockerfile checks the library in the image against the same
value and the plugin refuses to start with any other library. A change to the library is therefore: build, review the
new hash (the failure line prints it), set it in `SelfTest.cs`, commit, build again (the `ffi` stage comes from the
cache). The value today is the library of `pqz3`; plan Task 13 sets the one of `pqz4`. `clang` in the Dockerfile is
pinned to exact Debian 12 package versions.

The commands show the first image label, `pqz1`. The current image was built with the label `pqz2`
(`runs/2026-10-17-image-pqz2.txt`). The multi-recipient calibration was `calibrate.sh pqz2 --ops 7`: it writes only
the op 7 rows (`runs/2026-10-17-calib-ops7*`) and leaves `chain/engine-pqz.json` unchanged, because those rows join
the live rows in a second schedule.

**`FFI_REV` (2026-10-21).** On main the library sources moved on after the reviewed build (pqzl-fs3 Task 5: the PQZL
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
`engine.Pqz` keeps the two schedules the testnet ran before (PQZL rows with the v2 id `0x2e07e6ed…`, which the reviewed
`pqz3` library verifies; copy in `runs/2026-10-21-testnet-engine-pqz.json`); `chain/engine-pqz.json` on main already
carries the v3 id `0x8079d65b…` for the `pqz4` roll-out (plan pqzl-fs3 Task 13) and does not match this image. Procedure:
[chain/RUNBOOK.md](chain/RUNBOOK.md#nethermind-220-and-amsterdam-on-the-scaas-testnet-executed-2026-10-21); log
`runs/2026-10-21-testnet-2.2.0.txt`.

**Gas-rule headline** ([full report](runs/2026-10-21-glamsterdam-gas-impact.md)): (1) the EIP-7976 calldata floor (64
gas per byte) must stay under 2^24 (EIP-8037), so **no transaction carries more than ≈ 261,909 calldata bytes**:
every PQZH TRANSFER / BURN / REFRESH / op 7 input and PQZL op 7 M = 8 with the auditor are now refused (measured), and
the 16k op 7 M = 8 (309,591 B) can never fit; (2) EIP-8038's 10,000-gas storage write puts the 16k `ROLL_MAX` = 192
rollover at ≈ 16.6–18.0 M, so `ROLL_MAX` under 0.75 · 2^24 becomes ≈ 80–96 [estimate]; (3) the precompile prices are
unchanged (every probed row = formula); (4) every SSTORE2 op blob becomes ≈ 26–32 M of state gas.

## Runbook

[chain/RUNBOOK.md](chain/RUNBOOK.md) has every step, in order, for:

- **the copy** (Tasks 7–8): the rehearsal on a replica of chain 7622. Executed; the gate passed on 2026-10-16, with
  the checklist in `runs/2026-10-15-rehearsal.txt`;
- **the live roll-out on chain 7622** (Task 10): back up, then reset the chain with `engine.Pqz` active from block 0
  (owner decision 2026-10-15). Executed on 2026-10-16, log `runs/2026-10-16-live.txt`;
- **adding the multi-recipient transfer (op 7)** to the running chain with a second schedule. Executed on 2026-10-17,
  log `runs/2026-10-17-s8-live.txt`.
- **Nethermind 2.2.0 + Amsterdam**: the SCaaS testnet reset onto `2.2.0-pqz3` with Amsterdam from block 1. Executed on
  2026-10-21, log `runs/2026-10-21-testnet-2.2.0.txt`.

## Results (2026-10-15 to 2026-10-17)

| Task | Result | Log |
|---|---|---|
| 1–3 tests | 36 / 36 in the pinned SDK image | `runs/2026-10-15-test.txt` |
| 4 harness | 1 h clean: 6,955,371 inputs, 8 threads + GC pressure, status 3 = 0, `…01` = honest inputs | `runs/2026-10-15-harness-1h.txt` |
| 5 image | `pqz1` = `sha256:c53359a69bfa…`, library `12495e8b…7d87`, no hooks / GMP / MPFR / HEXL, never pushed | `runs/2026-10-15-image-pqz1.txt` |
| 6 calibration | `t_ecMul` 17 µs; rows 2.567–5.409 M gas; `selftestGas` 2,567,000; ML-DSA 49,000 / 68,000 | `runs/2026-10-15-calib.txt` |
| 7 copy | the stock image ignores `engine.Pqz`; path A before / after T, probe 111, e2e 53; path B probe 112, e2e 53 | `runs/2026-10-1[56]-copy-*.txt` |
| 8 rehearsal | burst 429s, 80 M ramp + full block (79.24 M gas), kill drill, rollback | `runs/2026-10-15-rehearsal.txt` |
| 10 live roll-out | chain 7622 backed up and reset with `engine.Pqz` from block 0 (image `pqz1`); genesis hash unchanged; probe and e2e passed | `runs/2026-10-16-live.txt` |
| S8 multi-recipient transfer (op 7, P6-ANON) | plugin rows per `(id, M, auditorOn)` (plan D19), 41 / 41 tests; harness 60 min CLEAN (4,577,772 inputs); image `pqz2` (library `4fc1a6a2…`); multi-recipient calibration 14 rows 3,625,000–6,177,000 gas; copy path A (pqz1 → pqz2, data kept) before / after T, e2e 86 ok; **live on 7622** 2026-10-17: second schedule at T = 1792205116, probe 389 ok before and after T, e2e 76 ok | `runs/2026-10-17-*` |

| Nethermind 2.2.0 + Amsterdam | port tests 46 / 46; image `2.2.0-pqz3` (library `16dd99ce…` from `1adbd563`); **SCaaS testnet reset** 2026-10-21 with Amsterdam from block 1: `PQZ-START`, genesis hash unchanged, probe all checks passed (input refusals over the floor included), e2e 76 ok, 64 KiB deploy (see the log) | `runs/2026-10-21-*` |

In this table, "path A" and "path B" are the two ways to switch the precompiles on (a future timestamp, or from
genesis; see the [runbook](chain/RUNBOOK.md)); "probe" and "e2e" count the checks that passed in `chain/probe.sh` (read-only
calls: chain id, genesis hash, self-test, every test vector and its gas) and `e2e.py e2e` (real transactions).
