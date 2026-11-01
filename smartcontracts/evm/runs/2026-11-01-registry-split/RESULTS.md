# UARegistry size spike: R1′, R2, one or two libraries (typed-signing f8a26a10)

Scratch only. Everything is in `variants/`: `baseline`, `r1` (R1′), `r2`, `r1r2` (two libraries), `one` (one library), `store`
(struct and helper moves, no lever). `levers/` holds the sources and the generators; `f3`, `f7`, `f8`, `f9` are compile-only
measures. Rerun all: `cd variants && ./run-all.sh`. Forge 1.8.5, solc 0.8.37, legacy codegen, optimizer 200, `isolate = true`.

## Recommendation

R2 alone: the registry's deployment fits a 60 M block at the lowest total bytes that fits (59,305 B), with no pointer cast.
R1′ on top only if the registry's own size matters more than +6,797 B in total. Not the one-library form: its library does
not fit a 60 M block, and the views cannot be pinned read-only.

## Sizes and deployment

| Variant | `UARegistry` runtime | init | Libraries runtime | Sum runtime | State gas `runtime × 1,530` |
|---|---:|---:|---:|---:|---:|
| baseline | 46,716 | 53,718 | none | 46,716 | 71,475,480 |
| R1′ | 39,288 | 46,143 | `UAViewLib` 17,885 | 57,173 | 87,474,690 |
| R2 | 28,048 | 34,966 | `UARegisterLib` 31,257 | 59,305 | 90,736,650 |
| R1′ + R2, two libraries | 16,960 | 23,731 | 17,885 + 31,257 | 66,102 | 101,136,060 |
| R1′ + R2, one library | 16,960 | 23,731 | `UARegisterLib` 41,875 | 58,835 | 90,017,550 |

`store` alone: 46,715 B, 53,717 B: the struct at slot 0 and the helper moves cost nothing.

Forge-simulated, each deployment its own transaction, CREATE2 with a salt, 20 kinds (`SpikeDiff.test_deployGas`):

| Transaction | Regular | State | Total | Fits 60 M | Gate `runtime × 1,530 + 2^24` |
|---|---:|---:|---:|---|---:|
| baseline `UARegistry` | 3,593,112 | 71,659,080 | 75,252,192 | no | 88.3 M |
| R1′ `UARegistry` | 3,107,736 | 60,294,240 | 63,401,976 | no | 76.9 M |
| `UAViewLib` | 1,170,328 | 27,547,650 | 28,717,978 | yes | 44.1 M |
| R2 `UARegistry` | 2,392,984 | 43,097,040 | 45,490,024 | yes | 59.7 M |
| `UARegisterLib` (two-library form) | 2,026,392 | 48,006,810 | 50,033,202 | yes | 64.6 M |
| R1′ + R2 `UARegistry` (both forms) | 1,674,136 | 26,132,400 | 27,806,536 | yes | 42.7 M |
| `UARegisterLib` (one-library form) | 2,706,328 | 64,252,350 | 66,958,678 | no | 80.8 M |

`UARegisterLib` in the two-library form fits by simulated gas, not by the `DeployBase` gate formula; that gate runs for the
registry only today. The one-library form does not fit by either.

## Stub forms in a `view` function

| Form | solc 0.8.37 | Result |
|---|---|---|
| raw assembly `delegatecall` | refused | "Function cannot be declared as view because this expression (potentially) modifies the state." |
| `address(lib).delegatecall(...)` | refused | same message |
| assembly `staticcall` to the library | accepted | useless: runs in the library's own storage |
| high-level library call | accepted | R1′ + R2 registry 22,265 B: decodes and re-encodes |
| non-view forwarder, pointer cast to `pure` in assembly (used here) | accepted, `view` and `pure` | 16,960 B: no return decoder; the return encoder stays |
| same, stubs without `returns` | accepted, cannot implement `IUARegistry` | 15,118 B, `outputs: []` in the ABI: fails the Blockscout point; compile-only |
| same, via-IR | accepted | R1′ 38,491; R2 26,428; R1′ + R2 15,783 (libraries 14,600 / 32,618, one library 40,870); baseline 46,071. Coders go. Sizes only: not tested |

Legacy codegen writes the return encoder in the external wrapper whatever the body does, and zero-initialises the return
variable, so the assembly `return` leaves that code dead but present. The cost of staying legacy is 1,842 B (16,960 − 15,118).
Residual Yul utilities in `UARegistry`: 14,970 (baseline), 12,654 (R1′), 10,569 (R2), 6,809 (R1′ + R2). Most of what stays
in the last figure is the entries' parameter decoders, which the wrapper also always writes.

Stub cost, marginal bytes (`levers/stubcost.py`, 27 of 28 stubs; `checkedOf` not measured, the constructor calls it):
26 for a shared decoder and shared encoder (`uaOf`, `popOf`, `keyOf`, …), 40–122 for value returns with their own decoder,
110–308 for struct returns (`registrationOf` 308, `frostKeyOf` 305, `msigOf` 208). Mean 102, against the 60–90 estimate.

## Read-only pin by opcode scan (`opscan.py`, `LinkClosure._walk` rules)

| Variant | Where the views run | Scan | Pin |
|---|---|---|---|
| baseline | `UARegistry` | SSTORE 21, LOG 5, CREATE 1 | no |
| R1′ | `UAViewLib` | SLOAD 39, STATICCALL 16, nothing else listed | yes |
| R2 | `UARegistry` | no SSTORE, LOG, CREATE, SELFDESTRUCT; DELEGATECALL 1 | no direct write, but the one DELEGATECALL reaches the writing library |
| R1′ + R2, two libraries | `UAViewLib` | SLOAD 39, STATICCALL 16 | yes |
| R1′ + R2, one library | `UARegisterLib` | SSTORE 21, LOG 5, CREATE 1 in the same code | no |

No library has CALL, CALLCODE, DELEGATECALL or SELFDESTRUCT. A scan pins the library; which library a stub reaches is the
registry's source. In the one-library form the views rest on solc's `view` check alone: a stub reached by a plain CALL
delegates without the static flag. Its 9 writing selectors do not equal any view stub's selector (checked).

## Duplication, two libraries against one

7,267 B, 11.1 M state gas: `UAKinds` 3,215, ABI coders 2,838, `UAStore` (key parsing, `kemAt`, `registration`) 585,
`SSTORE2` 347, dispatch and library code 214, metadata 68. `UAKinds.name` is in three places (registry and both libraries).

## ABI

`forge inspect UARegistry methodIdentifiers`: all 53 selectors identical in every variant. Whole JSON ABI: identical for R1′.
Every R2 form loses `error SSTORE2WriteFailed` from the registry's ABI (solc lists errors a contract uses), so that revert
bubbles from the library without a name unless it is declared; functions, events and the other errors are unchanged. Stubs
keep the baseline's parameter and return names; adding them changed no code byte (metadata aside).

## Suites

`test/ua/*.t.sol`, `test/**/*Deploy*.t.sol`, `test/v2/LinkClosure.t.sol`: 37 suites, 432 tests (428 + 4 `SpikeDiff`), every
variant 330 pass, 102 fail. Same status and same reason for every test as baseline, in all four lever variants.

The 102 failures are not the levers: the scratch copy had no `smartcontracts/vectors`, and the only copy reachable without
git or the typed-signing worktree is the main checkout's, which predates typed signing (`UAPoP`, missing JSON keys). They
fail on baseline too. Those 102 include most of `UARegistryUA8` and the real-verifier `register` and `msig` flows.

To narrow that, `test/ua/SpikeDiff.t.sol` runs a scripted scenario with stand-in verifiers, no signed vector: every kind,
PQZ keys, KEM versions and hash commit, `storePqzPop`, `setPqzKey`, m-of-n `msig` PoP and KEM record with native and derived
members, gen 2 in front of gen 1. All 1,210 hashes of raw return bytes, revert data and logs equal baseline in every variant.

Test edits: `SpikeDiff.t.sol` added everywhere; in R2 forms `SigOkHarness` calls the library's internal `_sigOk`.
No linking edit: `new UARegistry` and `deployCodeTo` link by themselves under `forge test`.

## Gas (`SpikeDiff.test_gas`, forge, stand-in verifiers, delta to baseline)

| Path | Baseline | R1′ | R2 | R1′ + R2 two | one |
|---|---:|---:|---:|---:|---:|
| `requireAuthorized` single keys, per kind | 16,933–17,510 | +29 | +37 | −7 | −7 |
| group and PQ kinds | 19,560–23,921 | +11 | +15 | −7 | −7 |
| `zether-bls12381` | 19,583 | 0 | +4 | −6 | −6 |
| native EOA | 12,465 | −4 | 0 | −4 | −4 |
| native ERC-1271 | 14,332 | −12 | −11 | −12 | −12 |
| `msig` 2-of-2 | 49,678 | −37 | −43 | −248 | −248 |
| `kindOf`, `pqzKeyOf`, `chainUid` | 5,831, 8,438, 3,513 | 0 | 0 | 0 | 0 |
| `register` regular, per kind | 141,554–375,728 | −53…+43 | +6,037…+6,436 | same as R2 | +6,063…+6,563 |
| `register` state | | 0 | 0 | 0 | 0 |
| `registerMsig` regular | 134,288 | −72 | +8,809 | +8,809 | +8,939 |
| `recordOf`, off chain | 8,519 | +3,624 | 0 | +3,624 | +3,602 |

The hot path does not structurally move: the ± figures are code layout, the −248 the dropped `portable` branch. A holder with a
PQZ key and KEM key shows 1,459,096 in every variant: the calldata floor dominates, so its execution overhead is hidden.

## Choices

- Storage: `UAStore.Layout` at slot 0, the baseline's mappings in the same order. Slots 0–14 unchanged, checked with
  `forge inspect storageLayout`. Nothing re-arranged.
- Immutables, views: call back the existing getters on `address(this)` (`predecessor`, `kindEnabled`).
- Immutables, registration: a callback cannot give a verifier address without a new selector, so the entry appends 3 words to
  the forwarded calldata (`_cfg(kind)`, `_cfg(0x0142)`, the clone codehash); the rest calls back `predecessor`, `hederaNative`,
  `verifyBudget`, `verifyCap`, `kindOf`, `keyOwner`.
- `_sigOk` moved with registration, against the brief's default: the library cannot call it back without a new selector. A
  derived `msig` member goes through `requireAuthorized` on `address(this)`; the verifier call stays in the registry. The native
  member rule (`_byCode`) is copied into the library.
- `UAKinds.name` is not off-chain only: `tag`, so `uaMessage` and `uaOf`, use it on the hot path. Its 1,123 B stay. `groupName`
  leaves with R2.

## On-chain callers

PUSH4 scan of every `src/` artifact (`exp/selscan.py`): only `chainUid`, `kindOf`, `pqzKeyOf`, `requireAuthorized`. Gen 2 calls gen 1
through the same ABI; all those selectors stay, and `SpikeDiff` compares the forwarded reads.

## Auditor view

`UARegistry` non-comment lines: 994 baseline, 754 R1′, 510 R2, 366 R1′ + R2; libraries 234 / 511 / 745, `UAStore` 112.

- DELEGATECALL into linked libraries. Needs a pin like `test_libraryOpcodes`: these libraries are outside the token closure
  `LinkClosure` covers.
- The pointer cast defeats the view checker, in one function.
- The appended words sit after attacker-shaped calldata: read by position from the end, so not forgeable, but a new pattern.
- `requireAuthorized` as a self-call adds a frame per derived member on the PoP path; `MSIG_MEMBER_GAS` was measured without it.
- `s.slot := 0` needs a layout pin; `test/v2/Layout.t.sol` does not cover the registry.
- CREATE2: init code embeds library addresses, so the registry's address depends on how the libraries are deployed. `DeployBase`
  needs them deployed first at fixed addresses, and `size-baseline.json` needs an `UARegisterLib` entry.

## Not measured

- The 102 vector-bound tests, on any variant.
- Suites outside the brief's list (`test/pqz`, `test/zether` beyond the deploy test, the rest of `test/v2`).
- Via-IR behaviour and hot path: sizes only.
- A `forge script` broadcast with the libraries.
- `checkedOf` stub bytes; PoP gas at `verifyBudget` through the self-call; execution overhead under the calldata floor.
