# Spike PACK: op 7 M = 8 and tight coefficient packing at parameter set (a), Amsterdam (plan 5h part B, research)

**Status:** research, 2026-10-21 (owner: "làm 4 việc đó đi, để có con số rõ ràng"). No `src/` change: every number is
the as-built token in a size-swapped work tree (`gasa.sh`, as `../p16k/gas16k.sh` did for 16k), the packed layouts are
patches applied in that work tree only (`pack46.patch`, `pack51.patch`). Research is not a decision: §5 recommends,
the owner decides.

**Set (a)** (owner 2026-10-21): n = 2304 (k = 36), q = 61,275,424,977,257 ≈ 2^45.80, Δ = 233,747,196 = ⌊q / 2^18⌋,
`K_MAX` 4,096; `pk` / `u` 18,432 B, `ct` 18,560 B, `acc` 580 words (`../n-study/results-n-study.md` §5 row n2304 K4096).

**Rules.** Ethereum Amsterdam: EIP-8037 state gas, EIP-8038 storage repricing, EIP-7976 calldata floor, EIP-2780
intrinsic; Foundry 1.8.5 (`evm_version = "amsterdam"`, `experimental = true` in the work tree). Per transaction:
**regular gas ≤ 2^24 = 16,777,216**; `ROLL_MAX` rule: regular ≤ 0.75 · 2^24 = 12,582,912; **total (regular + state) ≤
an Ethereum-like 60 M block**. Never gas price 0, never the testnet's 200 M limit. Op blobs stay in contract state.

**Convention** (Task 7 fix round 1 / Task 7b): every row is a **relayed full transaction** — `mtxExecute` from a fresh
relayer, non-zero ABSOLUTE outer fee 7, cold implementation and libraries — and reports regular gas before refunds
(intrinsic, calldata 4 / 16 or the EIP-7976 floor, execution, the precompile stand-ins) and EIP-8037 state gas apart.
Debits: BUNDLE, auditor on, fee, fresh `acc` reference unless noted. The `PQZ` precompile and ML-DSA-65 are `GasBurner`
stand-ins burning their price inside the transaction.

**Tags.** [measured] = a forge run whose log is in this directory; [estimate] = a model on measured numbers;
[inference] = a conclusion drawn here.

## 1. Headline

| | today's 64-bit lanes | **P46** (46-bit fields, 4 per 23 B) | P51 (51-bit lanes, 5 per word) |
|---|---|---|---|
| stored `ct` / op 1 blob / op 7 M = 4 blob / M = 8 blob (B) | 18,560 / 18,864 / 19,728 / 39,312 | **13,340 / 13,572 / 14,220 / 28,332** | 14,880 / 15,184 / 16,048 / 31,952 |
| op 1 regular / state / **total** [measured] | 8,087,495 / 29,634,570 / **37.72 M** | 8,305,847 / 21,537,810 / **29.84 M** | 8,316,352 / 24,004,170 / **32.32 M** |
| op 7 M = 4 regular / state / **total** | 6,977,632 / 31,641,930 / **38.62 M** | 7,194,398 / 23,214,690 / **30.41 M** | 7,205,709 / 26,011,530 / **33.22 M** |
| op 7 M = 8 (G = 2) regular / state / **total** | 10,542,118 / 62,388,810 / **72.93 M** | 10,833,731 / 45,589,410 / **56.42 M** | 10,849,273 / 51,128,010 / **61.98 M** |
| fits 2^24 regular? | all yes | all yes | all yes |
| fits a 60 M block? op 1 / M = 4 / M = 8 | yes / yes / **no** | yes / yes / **yes (3.6 M margin)** | yes / yes / no (+2.0 M) |
| `ROLL_MAX` (relayed full tx ≤ 12,582,912) [measured] | **96** (12,035,571) | **80** (12,214,487) | **144** (12,224,303) |
| rollover per entry + fixed (fit) | 47,563 + 7,469,523 | 79,824 + 5,828,567 | ≈ 43,650 + ≈ 5.96 M (a reduce every 32) |
| regular gas per credit rolled (at `ROLL_MAX`) | 125,371 | 152,681 | 84,891 |
| prepare-acc, both halves: regular / state | 7,271,622 / 57,381,120 | 5,290,004 / 41,420,160 | 5,873,564 / 46,120,320 |
| calldata (`mtxExecute` bytes) op 1 / M = 4 / M = 8 | 72,068 / 77,220 / 114,212 | unchanged | unchanged |
| precompile input / pqz-stmt / proofs | — | unchanged | unchanged |

Precompile prices [estimate]: today's PQZL v3 rows (auditor on) × 2304 / 2048 = 1.125 (as Task 7 used × 1.25 for
n = 2560): op 1 5,409,000 → **6,085,125**, op 7 M = 4 4,121,000 → **4,636,125**, op 7 M = 8 6,177,000 → **6,949,125**;
ML-DSA-65 68,006. Proof sizes: R_TX 48,724 B and txm4 52,950 B (set (a) codegen, `../n-study/`); **txm8 (G = 2)
70,353 B [estimate]** = 52,950 × 76,002 / 57,202 (the 16k codegen txm8 / txm4 ratio; no set (a) txm8 spec exists).

1. **Part 1 [measured + estimate].** At set (a) with today's lanes, op 7 M = 8 (G = 2) fits 2^24 regular easily
   (10.54 M; the precompile row may grow to 13.18 M, 1.90×, before it does not) but **cannot fit a 60 M block at any
   precompile price**: its state gas alone is 62.39 M (one SSTORE2 blob of 39,312 B: 60.15 M at 1,530 / B + 183,600
   for the account, then ≈ 2.06 M of new slots at 97,920). op 1 and op 7 M = 4 fit both limits; a 60 M block holds one
   of them.
2. **Part 2 [measured].** Packing the stored ciphertexts at ⌈log2 q⌉ = 46 bits (P46) saves **8.10 M state gas per op 1,
   8.43 M per op 7 M = 4, 16.80 M per op 7 M = 8** (exactly the blob bytes saved × 1,530) and 15.96 M per account at
   prepare, for **+0.22–0.29 M regular per debit** and `ROLL_MAX` 96 → 80. op 7 M = 8 then fits a 60 M block (56.42 M);
   two op 1 debits fit one 60 M block (59.69 M) instead of one. P51 saves less (5.63 M per op 1) but makes the rollover
   cheaper (`ROLL_MAX` 144); it leaves op 7 M = 8 over 60 M.
3. **The precompile, pqz-stmt and the proofs do not change [inference].** The calldata `out`, the statement
   (precompile input) and the proofs keep their 64-bit `be8` lanes; the token packs `out` into the blob and unpacks
   entries into the statement. Off-chain readers of blobs and the hint do change (§3.6).

## 2. Part 1: op 1, op 7 M = 4, op 7 M = 8 at set (a), today's lane format (`gas-a64-r128.txt`, `gas-a64-r96.txt`)

Relayed full transaction, fee 7, auditor on, fresh reference (op 1 also with a materialised `acc` read from its 580
slots, no hint: the op 1 worst case).

| form | proof B | calldata B | zero B | EIP-7976 floor | regular | state | total | ≤ 2^24 | ≤ 60 M |
|---|---|---|---|---|---|---|---|---|---|
| op 1, fresh ref | 48,724 | 72,068 | 11,528 | 4,627,352 | 8,087,495 | 29,634,570 | 37,722,065 | yes (8.69 M margin) | yes (22.3 M) |
| op 1, materialised `acc`, no hint | 48,724 | 72,068 | 11,527 | 4,627,352 | 9,556,388 | 29,732,490 | 39,288,878 | yes | yes |
| op 7 M = 4 (G = 1) | 52,950 | 77,220 | 11,913 | 4,957,080 | 6,977,632 | 31,641,930 | 38,619,562 | yes | yes |
| **op 7 M = 8 (G = 2)** | 70,353 [estimate] | 114,212 | 19,300 | 7,324,568 | **10,542,118** | **62,388,810** | **72,930,928** | **yes (6.24 M margin)** | **no (+12.9 M)** |

- Regular gas includes the precompile stand-in [estimate]; without it (row − precompile − 68,006) the EVM part of op 7
  M = 8 is ≈ 3.52 M. The floor (7.32 M) is below the regular gas in every row, so the standard path binds.
- **Precompile tolerance for M = 8**: regular stays ≤ 2^24 while the op 7 M = 8 row is ≤ 13,184,223 (1.90× the
  6,949,125 estimate); the 60 M block is out of reach because state gas alone (62.39 M) exceeds it [inference].
- State gas of a debit = the op blob (SSTORE2: 1,530 per code byte + 183,600 for the new account) + the new slots
  (97,920 each: the credits' pending slots, the entry pointer, the relayer's fee balance): M = 8's blob is 39,312 B
  (two `u` of 18,432 B).
- `ROLL_MAX` at set (a), today's lanes: **96** — relayed full tx regular 12,035,571 (margin 547,341), 112 → 12,796,579
  over; exactly linear, 47,563 per entry + 7,469,523 (the n-study estimate 47,563 + 7,501,819 holds). Prepare-acc half
  0 / 1: regular 3,635,811, state 28,690,560 (290 new slots), total 32,326,371 each.

## 3. Part 2: the packed stored layouts

### 3.1 What is packed, and what is not

Only what the token **stores**: the op blobs (SSTORE2 code: `u`, every `v`) and the materialised `acc` slots. The
calldata `out`, the hint's role, the statement buffer and the precompile input keep 64-bit `be8` lanes; keys (the
registry's SSTORE2 `pk`) are untouched (registry layout, UA-6). The token packs `out` when it writes the blob and
unpacks entries / `acc` when it builds `T` and the statement; views (`pqzAcc`, `pqzPendingCt`, disclosure) return the
64-bit form.

| layout | coefficient | `u` (2304) / `v` (16) | `ct` | `acc` slots | unreduced sums | zero-slot guard (D3) |
|---|---|---|---|---|---|---|
| today | 64-bit lane, 4 per word | 18,432 / 128 | 18,560 | 580 | 2^18 terms | `ACC_MARK` (bit 255) |
| **P46** | 46 bits, **4 coefficients = one 64-bit-lane word = 23 bytes**, byte-aligned stream | 13,248 / 92 | 13,340 | **417** | none in the stream (memory keeps 64-bit lanes) | each slot stores `not(stream word)`: a zero slot would mean every whole 46-bit field in it is 2^46 − 1 ≥ q, impossible for a reduced `acc` (every 32-byte window holds ≥ 4 whole fields; the last slot's padding becomes ones) |
| P51 | 51-bit lane, 5 per word (bit 255 free) | 14,752 (461 words) / 128 (4 words) | 14,880 | 465 | ≤ 36 terms of ≤ q (36·q < 2^51): reduce every 32 rollover entries | `ACC_MARK` |

Other layouts considered [inference]: a radix-q big-integer packing reaches 2320 · log2 q = 13,282 B per `ct`
(−0.4 % against P46) at the cost of a 256-bit division chain per word — not worth it; 48-bit lanes (5 per word,
4 terms of headroom) store as much as P51 with less headroom; "P46 blobs, 64-bit `acc`" keeps the blob saving but not
the prepare / fixed-rollover saving (`ROLL_MAX` ≈ 64 [estimate]: P46's 79,824 per entry on today's 7.47 M fixed part);
"P51 blobs, P46 `acc`" trades 2.47 M of state per op 1 for a cheaper rollover — dominated by P46 on the recurring item.

### 3.2 The change (work tree only; `pack46.patch`)

- `PqzCt`: `PKP`, `VP`, `CTP`, `ACC_WORDS`; `packCd` / `packMem` (64-bit word → 23 bytes, two mask steps), `expandAt`
  (in place, descending: 23-byte groups → 64-bit words), `unpackCt` / `packCt` / `packV`; `loadBlob` copies the packed
  `u ‖ v` and expands; `addBlob` (fused unpack + add, for `T`'s ≤ 16 inline entries); `addBlobEO` + `combineEO` for
  the rollover (see 3.4).
- `PqzCore`: `accWords[417]`; op 1 / op 7 / burn blobs written packed in ascending order (`salt ‖ P(u…) ‖ (P(v_j) ‖
  [P(v_a,j)] ‖ UA_j) ‖ P(v_f)`), every `uOff` / `vOff` / leg stride on `PKP` / `VP`; `_accOf` reads 417 slots (or the
  packed hint) and expands; `_window` sums packed entries; disclosure (`_legOf`, `_bundleShape`, `rOf`) on the packed
  strides, `u`, `v` expanded into the statement.
- `PqzStateLib`: the rollover packs the reduced sum, writes 417 slots of `not(word)`, `accHash = keccak(packed
  stream)`; prepare-acc halves of 209 + 208 slots; `accOf` / `pendingCt` views unchanged (they go through `_accOf`
  / `loadBlob`).
- Pins and tests in the work tree: the gas fixture's blobs are packed (`_blobCode`), credits point at `16 + PKP`, the
  D3 slot check walks `ACC_WORDS`, `accHash` is compared with `packCt(acc)`; `PqzPackRoundTrip.t.sol` (random /
  all-`q − 1` / zero round trip); `PqzPackMicro.t.sol`.

P51 (`pack51.patch`) changes the same call sites, but its working sums stay packed (`addMemP`, `subMemP`, `trivialP`,
`reduceP` on 5-lane words), and `_total` unpacks `T` straight into the statement (`unpackTo`).

### 3.3 Measurements (`gas-a46-r128.txt`, `gas-a51-r256.txt`, `gas-a64-r128.txt`; pins: `gas-a*-r{96,80,144}.txt`)

Relayed full transaction, fee 7; precompile stand-ins as §2.

| | 64-bit: regular / state / total | P46: regular / state / total | P46 Δ regular / Δ state | P51: regular / state / total | P51 Δ regular / Δ state |
|---|---|---|---|---|---|
| op 1, fresh ref | 8,087,495 / 29,634,570 / 37,722,065 | 8,305,847 / 21,537,810 / 29,843,657 | **+218,352 / −8,096,760** | 8,316,352 / 24,004,170 / 32,320,522 | +228,857 / −5,630,400 |
| op 1, materialised, no hint | 9,556,388 / 29,732,490 / 39,288,878 | 9,418,779 / 21,635,730 / 31,054,509 | −137,609 / −8,096,760 | 9,535,017 / 24,102,090 / 33,637,107 | −21,371 / −5,630,400 |
| op 7 M = 4 | 6,977,632 / 31,641,930 / 38,619,562 | 7,194,398 / 23,214,690 / 30,409,088 | +216,766 / −8,427,240 | 7,205,709 / 26,011,530 / 33,217,239 | +228,077 / −5,630,400 |
| op 7 M = 8 (G = 2) | 10,542,118 / 62,388,810 / 72,930,928 | 10,833,731 / 45,589,410 / 56,423,141 | +291,613 / −16,799,400 | 10,849,273 / 51,128,010 / 61,977,283 | +307,155 / −11,260,800 |
| prepare half 0 | 3,635,811 / 28,690,560 / 32,326,371 | 2,651,034 / 20,759,040 / 23,410,074 | −984,777 / −7,931,520 | 2,942,826 / 23,109,120 / 26,051,946 | −692,985 / −5,581,440 |
| prepare half 1 | 3,635,811 / 28,690,560 / 32,326,371 | 2,638,970 / 20,661,120 / 23,300,090 | −996,841 / −8,029,440 | 2,930,738 / 23,011,200 / 25,941,938 | −705,073 / −5,679,360 |
| rollover at `ROLL_MAX` | 96: 12,035,571 / 195,840 | 80: 12,214,487 / 195,840 | — | 144: 12,224,303 / 195,840 | — |
| `ROLL_MAX` + 16 (over) | 112: 12,796,579 | 96: 13,491,671 | — | 160: 12,969,461 | — |

- **State saved = blob bytes saved × 1,530 exactly** (op 1: 5,292 B; op 7 M = 4: 5,508 B; M = 8: 10,980 B; P51: 3,680
  / 3,680 / 7,360 B) and new slots × 97,920 at prepare (P46 163, P51 115 fewer) [measured].
- **Regular added per debit** (+0.22 M; +0.29 M for M = 8): packing `out` into the blob (23 of every 32 bytes) and
  expanding the reference blob into `T`. Reading a materialised `acc` gets cheaper (417 cold slots instead of 580:
  −342,300), so op 1 with a materialised `acc` costs less regular gas than today.
- **Calldata**: unchanged (72,068 / 77,220 / 114,212 B), so the floor is unchanged. The hint becomes the packed `acc`
  (13,340 B instead of 18,560: −83,520 calldata gas when used) [estimate; hint path not measured].
- **Rollover scans** (`test_pack_scanRoll`, 16-entry steps, regular): 64-bit 8,230,531 + 47,563 / entry; P46
  7,105,751 + 79,824 / entry; P51 6,663,379, 7,408,525, 8,053,613, … 17,140,163 at 256 (≈ 43,650 / entry, the
  32-entry `reduceP` ≈ 100 k shows as alternating steps of 745,146 / 645,088).

### 3.4 Why P46's rollover is dearer, and the accumulator (`gas-a46v1-r128.txt`, `gas-a46v2-r128.txt`, micro)

A stored P46 entry must be spread back into 64-bit lanes before it can be added. Micro-benchmark (`test_micro`, one
entry of 580 words, warm) [measured]: today's `addMem` **29,702**; P46 fused unpack-and-add `addBlob` **122,923**; the
rollover accumulator `addBlobEO` **67,083**; the two `extcodecopy` alone 4,668. The first P46 build (naive loop) gave
138,220 per rollover entry (`ROLL_MAX` 48), an unrolled two-mask spread 135,637 (48): the spread, not the loop, is
the cost. `addBlobEO` adds each 23-byte group as loaded into two accumulators (`c3, c1` masked in place; `c2, c0`
after one shift), each field with a 46-bit gap above it for the carries, and spreads once per rollover
(`combineEO`): **79,824 per entry, `ROLL_MAX` 80**. The debit path (≤ 16 inline entries) keeps `addBlob`.

### 3.5 Correctness checks (`gas-a*-r{96,80,144}.txt`, `func-a*.txt`)

- `PqzPackRoundTripTest`: 256 random canonical ciphertexts, all `q − 1`, all zero: pack → `CTP` bytes → unpack = the
  input, both layouts [measured].
- The pins at each layout's own `ROLL_MAX` (`PqzStatePinGasTest`, `PqzStateTrivialRollGasTest`, `PqzPackGasTest`):
  `test_gas_rollMax` rolls `PRE + ROLL_MAX` entries of all-`q − 1` coefficients and checks every lane of `pqzAcc` is
  `q − (PRE + ROLL_MAX)` (the unspread accumulator, P51's periodic reduce, pack / store / load / unpack); the D3 tests
  check that no `acc` slot is zero after a TRIVIAL-only rollover and that `accHash` matches. **All pass**
  [measured]: 64-bit at 96: 71 / 71; P46 at 80: 73 / 73; P51 at 144: 73 / 73 (with the round trip).
- Functional PQZ suites at set (a), differential (the fixture's statement vectors are n = 2048, so some tests fail at
  set (a) in every tree): 64-bit 56 / 80 pass, P46 52 / 80, P51 52 / 80 [measured]. The same 24 tests fail in all three trees (vector statements, n = 2048). Exactly **four more fail in both
  packed trees, each on a layout it pins, not on a value**: `test_multi_M8_twoGroups` asserts the 64-bit blob length
  (16 + 2·PK + 160·8 = 38,160; packed 27,504 / 30,800 — its eight `pqzPendingCt` checks, both `u` groups, pass
  first), `test_events` an event hash over `R`, `test_hint_staleFreshAndAfterDebit` a 64-bit hint,
  `test_restoreFromState` `accHash` = keccak of the 64-bit `acc`. Not covered at set (a) in any tree: the disclosure
  and statement-vector tests (they fail on the n = 2048 vectors before the packing matters).

### 3.6 The precompile input format

Both layouts keep the statement codec as it is: pqz-stmt reads 64-bit `be8` coefficients, the token unpacks `T`,
`out` stays in calldata as the prover wrote it, so the precompile, both cores, the provers and every proof are
unchanged and no `proofSystemId` bump is needed for the packing [inference]. What does change, off-chain and in the
spec: (1) the op blob layout (an indexer reading SSTORE2 code must unpack; the views return 64-bit), (2) the hint is
the packed `acc` and `accHash` is over the packed stream, (3) `ciphertextHash(ref)` = keccak of the packed `R`,
(4) `ZERO_HASH` (not used on the token's paths today) would become keccak of the packed zero `acc`. A packed statement
(pqz-stmt reading 46-bit fields) would cut the statement's coefficient bytes by 28 % and op 1 calldata by ≈ 5.2 KB
(−82 k regular at 16 / B) but changes the transcript, both cores and every prover for ≈ 1 % of the state saving: not
recommended [inference].

## 4. Per-operation economics [estimate from §3.3]

A credit is rolled once (unless spent inline), so an op 1 costs its own transaction plus one credit's share of
rollovers (`ROLL_MAX` rollover ÷ `ROLL_MAX`):

| | 64-bit | P46 | P51 |
|---|---|---|---|
| op 1 + 1 credit rolled | 37.85 M | **30.00 M (−20.7 %)** | 32.41 M (−14.4 %) |
| op 7 M = 8 + 8 credits rolled | 73.93 M | **57.64 M (−22.0 %)** | 62.66 M (−15.3 %) |
| rollovers to fill `acc` (4,095 units) | 43 | 52 | 29 |
| debits per 60 M block (op 1 fresh ref) | 1 | **2** (59.69 M) | 1 |

## 5. Recommendation [inference; the owner decides]

**P46**: store every op-blob and `acc` coefficient in 46 bits, four coefficients (one 64-bit-lane word) per 23 bytes,
`acc` slots as `not(stream word)`; the token packs `out` and unpacks into the statement; the rollover sums the packed
groups in two unspread accumulators. Costs: **+0.22–0.29 M regular per debit**, `ROLL_MAX` **96 → 80** (+27 k regular
per credit rolled), +195 lines in `PqzCt` and +82 / −48 lines over ≈ 15 call sites in `PqzCore` / `PqzStateLib`
(`pack46.patch`), the spec's §8.1 byte layouts and the off-chain readers of blobs / hint. Gains: **−8.10 M state per op 1, −8.43 M per op 7 M = 4,
−16.80 M per op 7 M = 8**, −15.96 M state and −1.98 M regular per account at prepare; op 7 M = 8 at G = 2 then fits
a 60 M block (56.42 M, 3.6 M margin; the precompile may reach ≈ 10.5 M = 1.52× before it does not) and a 60 M block
holds two op 1 debits. P51 is the fallback if rollover throughput matters more than state (`ROLL_MAX` 144, −5.63 M
per op 1, M = 8 still over 60 M). Today's 64-bit lanes leave M = 8 over 60 M at any precompile price.

**Open points (not decided here).** (1) M = 8 was measured at G = 2 as the brief asks; Task 7's O9 rule moved 16k's
M = 8 to G = 1 for the 144-hint security margin, which this spike did not re-examine at set (a). (2) Every precompile
price and the txm8 proof size are estimates (no set (a) txm8 spec, no calibration). (3) The hint path and disclosure
were not gas-measured; the disclosure tests fail on the n = 2048 vectors in every set (a) tree.

## 6. Files and reruns

| File | What |
|---|---|
| `gasa.sh` | the set (a) work tree (sizes, Amsterdam), `PACK=46` / `PACK=51` (/ `46v1`, `46v2`) applies the patch, runs forge |
| `pack46.patch`, `pack51.patch` | the packed layouts (src + the work tree's gas test, `PqzPackRoundTrip.t.sol`, P46 `PqzPackMicro.t.sol`) |
| `pack46v1.patch`, `pack46v2.patch` | the two earlier P46 loops of §3.4 (no rollover accumulator) |
| `runs.sh` | every forge run below (`scan`, `confirm`, `func`) |
| `gas-a64-r128.txt`, `gas-a46-r128.txt`, `gas-a51-r256.txt` | scans + op rows + prepare + round trip + micro |
| `gas-a46v1-r128.txt`, `gas-a46v2-r128.txt` | the earlier P46 loops |
| `gas-a64-r96.txt`, `gas-a46-r80.txt`, `gas-a51-r144.txt` | all pins at each layout's `ROLL_MAX` |
| `func-a64.txt`, `func-a46.txt`, `func-a51.txt` | the functional PQZ suites, differential (assertion hex lines trimmed) |
| `smartcontracts/evm/test/research/PqzPackGas.t.sol` | the research test (scan, op 1 / op 7 M = 4 / M = 8 relayed full tx at set (a)) |

```sh
# from the worktree root; W = a scratch dir; forge 1.8.5
sh pqz-core/pqzl/params/pa-pack/runs.sh $W scan      # the five scan logs
sh pqz-core/pqzl/params/pa-pack/runs.sh $W confirm   # the pins at 96 / 80 / 144
sh pqz-core/pqzl/params/pa-pack/runs.sh $W func      # the functional suites (after confirm)
```
