> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# EVM size levers for the named entries (typed-signing C0)

Written 2026-11-01 for the owner's lever choice, Task C0 of the `typed-signing` plan (TS-D18). Measure and report only: no lever is on the branch. The only ceiling is 65,536 B runtime; structural levers only, no byte-shaving. Raw figures, gas and suites: `smartcontracts/evm/runs/2026-10-31-typed-signing-c0-sizes.txt`. Gas and suites use the default set `n2304-kmax4096`.

## 1. Result

- **Part C does not fit without a lever.** `WrappedPqzToken` and `WrappedZetherToken` end at about 77.4 KB and 78.3 KB, so 11.9 KB and 12.8 KB over. The other four token kinds, the two wallets and `UARegistry` stay under.
- **Lever 2 alone frees about 9 KB per wrapped token and costs nothing.** It moves the `nonReentrant` body into two shared private functions. No suite breaks, and gas changes by −48 to +10 per call.
- **Recommended set: lever 2 + lever 1.** Every contract then fits, with about 3.8 KB of margin on both wrapped kinds. Lever 3 stays in reserve; levers 4 and 5 are not recommended.

The spike itself already fits, with 898 B left on `WrappedPqzToken` and 1,672 B on `WrappedZetherToken`.

## 2. How the projection was made

Two figures, because the entry cost alone understates the confidential forms.

- **Entry-cost floor.** Spike size plus the remaining entries at the measured marginal cost. Static entries only.
- **Full mock.** A compile-only copy with the whole token-side entry list of C2, C3, C4 and the C6 relay fee: every static named entry, the typed direct confidential ops with their Envelope and `ua*` entries, the typed statement views, `UASig` on the named path, `executeMetaTransaction`, `mtxExecuteWithFee` and the flat `uaUnwrap` removed. Library bodies are stubs: it measures what each entry costs the token, and it does not run. Generator: `runs/2026-10-31-typed-signing-c0-mock.py`.

Not in the mock: `ReceiverFee`, `WrapOrder` and the nested cancels (their hashes sit in `TradeLib`, about zero on the token), and `UASig` on the generic `ua*` entries, which keep `bytes auth`. Real C2–C6 code will differ from the mock, so treat a margin under about 1 KB as no margin.

**Measured entry cost** (`WrappedPqzToken`, three-argument static entries): +341 B for the first entry of a new argument shape, then +256 B per `mtx` and +260 B per `ua`. With lever 2 these are +218 B and +133 to +137 B.

**The jump width.** Once code passes 65,535 B the assembler widens every jump target from PUSH2 to PUSH3: 5,294 of them on the full `WrappedPqzToken`. So a build above the ceiling reads about 5.2 KB larger than its real excess, and on the spike two more entries read 65,235 B while four read 70,167 B. A figure above 65,536 B in the tables below carries that width; a figure below does not.

| Contract | HEAD | Spike | Left `mtx` + `ua` | Entry-cost floor | Full mock (PUSH2 width) | Against 65,536 B |
|---|---|---|---|---|---|---|
| `NormalToken` | 39,889 | 39,945 | 2 + 1 | 40,717 | 41,457 | under |
| `WrappedToken` | 49,652 | 50,770 | 7 + 3 | 53,342 | 54,557 | under |
| `NormalZetherToken` | 49,952 | 51,536 | 10 + 9 | 56,436 | 61,708 | under, 3,828 B left |
| `WrappedZetherToken` | 61,808 | 63,864 | 17 + 12 | 71,336 | 83,448 (78,300) | **over by 12,760 B** |
| `NormalPqzToken` | 50,652 | 52,236 | 9 + 8 | 56,620 | 60,424 | under, 5,112 B left |
| `WrappedPqzToken` | 62,616 | 64,638 | 16 + 11 | 71,594 | 82,726 (77,430) | **over by 11,900 B** |
| `MandateWallet` | 16,171 | 17,461 | 6 + 0 | about 19,000 | not mocked | under |
| `SmartKeyAccount` | 19,845 | 19,864 | 7 + 0 | about 21,700 | not mocked | under |
| `UARegistry` | 46,716 | 46,716 | none | 46,716 | 46,716 | under, no Part C entry |

## 3. Where the bytes are

| Contract (spike) | Total | Dispatcher and external bodies | Internal routines | Yul utilities (ABI coders) | `mtxSelectors` |
|---|---|---|---|---|---|
| `NormalToken` | 39,945 | 3,561 | 26,698 | 9,686 | 302 |
| `WrappedToken` | 50,770 | 5,920 | 33,686 | 11,164 | 1,123 |
| `NormalZetherToken` | 51,536 | 4,883 | 34,853 | 11,800 | 1,192 |
| `WrappedZetherToken` | 63,864 | 7,217 | 43,408 | 13,239 | 2,203 |
| `NormalPqzToken` | 52,236 | 4,799 | 35,649 | 11,788 | 1,094 |
| `WrappedPqzToken` | 64,638 | 7,493 | 43,830 | 13,315 | 2,104 |
| `UARegistry` | 46,716 | 2,389 | 35,484 | 8,843 | none |

The internal routines include the external function bodies solc emits as routines. The plan says seven tokens; six token kinds exist (`TokenKind`).

What is duplicated or inlined on `WrappedPqzToken`:

- **`nonReentrant`:** on about 75 entries, about 120 B each, 8,971 B in all. Legacy code generation copies a modifier into every function that uses it. The source map shows only 5,181 B of this, because the optimizer's shared blocks are charged to their other users.
- **The selector table:** `mtxSelectors` 2,104 B, a constant table.
- **The init path:** `TokenConfig` coders and `_requireUnused`, about 1.6 KB, run once per clone.
- **The `UAKinds.uaSig` shim:** 516 B plus its share of `uaCancelNonce` (722 B). C2 removes it.
- **Rare paths that need token internals:** `mtxPayReceiverFee` 880 B and `uaPayReceiverFee` 889 B call `_transfer` / `_uaMove`, so a library cannot take them without a re-entry hook.

`UARegistry` has no guard modifier and no named entries. Its largest routines are `UAKinds.name` 1,698 B and `_membersWorst` 1,128 B. It needs no lever.

## 4. The levers

Runtime bytes of the two wrapped kinds. "Spike" is each lever alone on the branch's code, "full" alone on the full mock. A figure above 65,536 B carries the jump width.

| Lever | `WrappedPqzToken` spike | full | `WrappedZetherToken` spike | full | Gas per call | Suites broken | Effort | Risk |
|---|---|---|---|---|---|---|---|---|
| none | 64,638 | 82,726 | 63,864 | 83,448 | — | — | — | — |
| 1. External libraries | 61,071 (−3,567) | 78,735 | 60,156 (−3,708) | 79,284 | −12 to +22 | 1 | small | low |
| 2. Shared `nonReentrant` body | 55,667 (−8,971) | 65,165 | 54,748 (−9,116) | 69,761 | −48 to +10 | 0 | one edit | low |
| 3. Views behind `fallback` | 56,274 (−8,364) | 73,406 | 58,834 (−5,030) | 77,786 | entries 0; a read +3,082 | not run | large | medium |
| 4. `optimizer_runs` 50 | 63,664 (−974) | 81,616 | 62,833 (−1,031) | 81,623 | +130 to +936, median PQZ row +652 | 5 | one line | medium |
| 4. `optimizer_runs` 1 | 63,214 (−1,424) | 81,190 | 62,432 (−1,432) | 81,192 | +563 to +6,078, median PQZ row +4,388 | 15 | one line | high |
| 5. `via_ir` | 56,206 (−8,432) | 79,182 | 56,189 (−7,675) | 80,099 | sample: −3,552 to +870 | not run | large | high |

**Lever 1.** Measured form: `initialize` hands the raw `initArgs` to the library, so no `TokenConfig` coder stays in the token, and the selector table moves behind a library call. The other token kinds keep their own, so their sizes are unchanged (+10 B). The broken test is `LinkClosure.test_libraryOpcodes`, which pins that a library holds no DELEGATECALL: the lever chains two libraries. That pin needs the owner's word, or the token can call the two libraries in turn (not measured).

**Lever 2.** `modifier nonReentrant() { bool outer = _enter(); _; _exit(outer); }` with the two functions `private` in `MetaTxBase`. It helps every future entry too, cutting the marginal entry from about 256 B to about 135 B. On the wallets it frees about 1.7 to 1.8 KB. Alone it leaves `WrappedPqzToken` only 371 B under, and `WrappedZetherToken` just over.

**Lever 2, tested variant.** Static entries handing `msg.data[260:…]` instead of `abi.encode(…)` gained nothing (+21 B on the spike, −193 B on the mock). Dropped.

**Lever 3.** 47 read-only functions leave the dispatch and a stateless module answers them, on the token's address. Views that other contracts read on chain stay (DEX, factory, `ZetherStatements`, `ZetherDisclosure`). The reads are `eth_call`s, so the +3,082 gas is never paid on chain. It needs a module per release, one more `env.deps` entry, a `fallback` with DELEGATECALL on every token, and casts at up to about 720 test call sites in 69 files. Those sites stop the test tree compiling, so the suites were not run. The module was not written: the size is measured by deletion.

**Lever 4.** Gas rises on every path and the size gain is small. At 50, the five broken tests are gas pins. At 1, fifteen break, and two of them are behaviour: `test_T_GAS_msigAtBudget` and `test_T_GAS_memberPopSizeFree` fail "authorizes with verifyBudget": the pinned verify budget stops being enough.

**Lever 5.** Measure only. A large gain alone, but it mostly overlaps lever 2: `via_ir` already deduplicates the modifier, so lever 2 + `via_ir` gives `WrappedPqzToken` 64,172 B and `WrappedZetherToken` 65,130 B on the mock. Each token compiles alone in 2 to 10 s, but `forge build src` is killed by the 4 GB scope, and the test tree in sparse mode at 6 GB as well. So no suite ran, and the cap was not raised (oomd). The gas sample covers only the public tokens: `mtxUnwrap` −3,552, `mtxExecute(unwrap)` −2,999, `mtxExecuteTransfer` −571, `transfer` +870. Build times are indicative: the machine is shared.

**TS-D18's alternatives.** The B′ module (the confidential named entries behind `fallback`) gives 73,398 B / 72,117 B alone, and dropping the envelope entries of the proof-authorised ops 74,267 B / 72,908 B alone. Neither fits on its own, and with lever 2 + lever 1 neither is needed.

## 5. Combinations on the full mock

| Set | `NormalZetherToken` | `WrappedZetherToken` | `NormalPqzToken` | `WrappedPqzToken` | Least margin |
|---|---|---|---|---|---|
| 2 | 52,224 | 69,761 (over) | 51,353 | 65,165 | does not fit |
| 2 + `optimizer_runs` 50 | 50,221 | 63,506 | 50,341 | 63,780 | 1,756 B |
| 2 + `optimizer_runs` 1 | 49,810 | 63,009 | 49,931 | 63,295 | 2,241 B |
| **2 + 1** | 52,234 | 61,704 | 51,363 | 61,378 | **3,832 B** |
| 2 + 3 | 50,713 | 60,335 | 46,903 | 56,422 | 5,201 B |
| 2 + B′ | 45,363 | 57,641 | 46,387 | 58,888 | 6,648 B |
| 2 + 1 + 3 | 50,723 | 58,332 | 46,913 | 54,409 | 7,204 B |

## 6. Recommendation

Take **lever 2 and lever 1** for C2–C6, as an owner decision.

- Lever 2 first: it is one edit, breaks nothing, and shrinks every token and wallet.
- Lever 1 for the margin: the init path and the selector table are hot-path free, and it keeps the selectors and the ABI.
- Hold lever 3 or B′ in reserve for the wrapped kinds if the real C3 / C4 code ends above about 64.5 KB. Both need a release module and a `fallback`.
- Leave `optimizer_runs` at 200 and `via_ir` off: they trade gas pins and a large re-verification for what lever 1 gives without either.

## 7. Findings for C3 and C4

- **Stack limit.** Appendix X.3's `mtxUnshield(Envelope, PqzBurnArgs, amount, recipient, proof, pqzAuth, accHint, sig)` and its `ua*` twin do not compile under the legacy code generator. The mock passes `amount` and `recipient` in one calldata struct, as `Unwrap` does; the signed struct keeps both fields. Zether's typed `mtxUnshieldUnwrap` needs a local for its `Env`.
- **The overload.** `mtxShield(Envelope, …)` makes `this.mtxShield.selector` and `abi.encodeCall(PqzLayer.mtxShield, …)` ambiguous, so sources and tests read the selector from `IConfidentialToken`. C3 and C4 meet the same on every overloaded op.
- **Gas of a named entry.** `mtxUnwrap` costs 602 gas more than `mtxExecute(unwrap)` on a warm lane (152,569 against 151,967), despite 128 B less calldata. It does not undercut the generic path, as one might assume.
- **Entry counts.** `WrappedPqzToken` has 18 + 12 entries by `_uaAllowed`, the plan says about 11.
- **`debit_min_gas`.** The spike moves the measured figure +680 to +720 at every set. Not re-pinned (owner ruling 2026-11-01); the figures are in the run log.

## 8. `UARegistry` split (2026-11-01)

Measured first on a scratch copy at typed-signing C2 (the table below, the owner's first ruling: not split). Owner ruling later on 2026-11-01: build R2 alone. Built in typed-signing R2; its figures close this section. Sources: `smartcontracts/evm/runs/2026-11-01-registry-split/` (spike), `smartcontracts/evm/runs/2026-11-01-typed-signing-r2-*` (built).

| Variant | Registry runtime | Libraries | Total | Largest transaction (forge simulated) |
|---|---|---|---|---|
| baseline | 46,716 | none | 46,716 | 75.3 M |
| R1′ views in `UAViewLib` | 39,288 | 17,885 | 57,173 | 63.4 M |
| R2 registration paths in `UARegisterLib` | 28,048 | 31,257 | 59,305 | 50.0 M |
| R1′ + R2, two libraries | 16,960 | 17,885 + 31,257 | 66,102 | 50.0 M |
| R1′ + R2, one library | 16,960 | 41,875 | 58,835 | 67.0 M |

- **R1′ falls short.** Legacy codegen writes the return encoder in the external wrapper whatever the body does, so the coders stay (12,654 B against 14,970 B). A raw `delegatecall` in a `view` function is refused; the working stub casts a function pointer past the view checker. Via-IR removes the coders, but its baseline is already 46,071 B.
- **R2 costs:** `register` about +6 k regular gas, `registerMsig` about +8.8 k, total bytes +27 %. The hot path stays: `requireAuthorized` within +37 gas. The 53 selectors stay; `SSTORE2WriteFailed` must be declared again. New patterns: three words appended to the forwarded calldata for the immutables, callbacks on `address(this)`, `_sigOk` moved to the library, the registry's CREATE2 address depends on the library.
- **Not measured by the spike:** 102 of 432 tests failed on every variant, baseline included, because the scratch copy lacked the branch's vectors. `register` with real signatures had run on no variant. A difference test with stand-in verifiers matched baseline on all 1,210 hashes. Owed before adopting R2; done below.

### Built (typed-signing R2, 2026-11-01)

| | `UARegistry` runtime | init | `UARegistryLib` runtime | Total runtime |
|---|---:|---:|---:|---:|
| pre-split (C6) | 46,716 | 53,718 | none | 46,716 |
| built | 27,997 | 34,970 | 31,315 | 59,312 (+26.9 %) |

Each deployment its own transaction, CREATE2 with a salt, 20 kinds + 0x0142 (`UARegistrySplit.test_deployGas`, forge simulated):

| Transaction | Regular | State | Total | Gate `runtime × 1,530 + 2^24` |
|---|---:|---:|---:|---:|
| pre-split `UARegistry` | 3,593,112 | 71,659,080 | 75,252,192 | 88.3 M |
| `UARegistry` | 2,392,984 | 43,019,010 | 45,411,994 | 59.6 M |
| `UARegistryLib` | 2,030,488 | 48,095,550 | 50,126,038 | 64.7 M |

These are the call frames. The largest registry transaction falls from 75.3 M to 50.1 M. As a whole transaction, intrinsic gas and calldata included, a real `forge script` broadcast on anvil (`runs/…-r2-deploy.txt`, every transaction) simulates `UARegistryLib` at 54.7 M and `UARegistry` at 46.5 M; forge sends the library by CREATE2 with the other libraries, the registry's init code embeds its address. The library's gate asks 64.7 M, about 10 M over that: its deposit is state gas, so the formula's 2^24 of regular room is mostly unused. The formula stays (owner rule). `Deploy.s.sol` broadcasts at 80 M and 100 M; at 65 M `NormalToken`'s gate (73.7 M) refuses it; at 60 M the library's gate refuses it, although the transaction would fit.

- **Hot path:** `requireAuthorized` single keys +37 gas, group and PQ kinds +15, `zether-bls12381` +4, native EOA +5, native ERC-1271 −49, `msig` 2-of-2 −38, the same at all four sets: the spike's +37 holds. The figure is sensitive to code form: a local variable in `_verifierCall` made it +45.
- **PQZ pins:** the PQZ gas table's `pqz` column does not move at any set (no calibrated row moves). The debit row moves +30 at every set; over `debit_min_gas`: +9,349, +9,390, +9,367, +9,418. The pin stays (owner ruling, until CG).
- **Writes:** `register` +6,055…+6,454 regular gas, `registerMsig` +8,841, state gas unchanged at every row. Rows under the calldata floor do not move, so the PQZ gas table's `register` with a proof is the one row that shows the proof copied twice: +21,427 to +26,927 by set. `storePqzPop` with a verify of the real cost (3.65 M), `n2816-kmax65536`, regular + state: 60,113,334 to 60,127,685 (+14,351), on gen 2 60,463,214 to 60,479,991 (+16,777); the TODO watch item's ≈ 59.9 M was low, the pre-split code is already over a 60 M block. An `msig` PoP at its bound (8 members near 1.4 M each) 11,443,002 to 11,489,473 regular gas: each derived member adds a `requireAuthorized` frame, and it still fits 2^24.
- **Differential:** the frozen source (`legacy/typed-signing/UARegistryPreSplit.sol`) against the split on the same inputs at the same addresses: return and revert data, logs, every storage slot written, every created contract, every call out. `UARegistrySplit.test_diff`: the spike's views, extended to writes and 75 negatives with exact errors, 3,614 rows. `UARegistryUA8Test.test_split_portableRowsSame`: portable.json's real signatures and verifiers.
- **One difference, malformed calldata only:** a nested offset is checked where it is read, and the library's calldata is 96 B longer, so an offset aimed at an appended word reads it as the caller's own argument where the pre-split code reverted. It reads public values and writes nothing a well-formed call could not.
- **`forge build --sizes` leaves out a library with no view function in its ABI,** so `scripts/size_gate.py` now measures every library from its artifact.

## 9. Lever 1 on real code (C3, 2026-11-01)

The owner's lever 1 on `WrappedZetherToken`, in the measured form of §4: `initialize` hands the raw `initArgs` to a library, so no `TokenConfig` coder stays in the token, and `mtxSelectors()` is a library call. The library is a new one, `ZetherWrappedLib`, in the release's link closure of `WRAPPED_ZETHER` only. The form in the mock put both functions in `ZetherLib`; that would have added a DELEGATECALL and `WrappedLib` to `NORMAL_ZETHER`'s closure for nothing.

| `WrappedZetherToken` | Runtime | Margin to 65,536 B |
|---|---|---|
| before C3 | 57,404 | 8,132 |
| C3, no lever 1 | 64,475 | 1,061 |
| C3, lever 1 | 60,759 | 4,777 |

The lever frees 3,716 B on the token. `ZetherWrappedLib` is 4,958 B and `init` chains two libraries, so `LinkClosure.test_libraryOpcodes` pins 2 DELEGATECALLs for it. Without the lever the kind is 25 B under the 64.5 KB stop line and C6 has entries to add, so it stays on.

The mock's 61,704 B was close. `NormalZetherToken` ends at 51,639 B (mock 52,234 B, no lever applied), `ZetherLib` at 19,560 B.

Two findings for C4:

- A `constant` written `keccak256(bytes(string.concat(...)))` is not folded by the compiler: the concatenation runs at every use. Written as one string literal per typehash, the same eight constants freed 2,016 B on the wrapped kind and on the normal one.
- A signed entry and its `ua*` twin share one private function that returns the struct words and the op's call. Two encoders per pair of entries would otherwise cost about 1,100 B on the wrapped kind.

