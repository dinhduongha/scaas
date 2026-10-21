> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ at parameter set (a): op 7 M = 8 and tight packing of stored ciphertexts (plan 5h part B, 2026-10-21)

Owner 2026-10-21: "làm 4 việc đó đi, để có con số rõ ràng" (do those four things, so the numbers are clear). Research
only: no `src/` change. Full tables, logs, patches and reruns:
[`pqz-core/pqzl/params/pa-pack/results-pack.md`](../../pqz-core/pqzl/params/pa-pack/results-pack.md).
Tags: [measured] = Foundry 1.8.5 under Amsterdam on the as-built token in a size-swapped work tree; [estimate] = a model
on measured numbers (precompile prices: today's PQZL rows × 2304 / 2048; the txm8 proof size); [inference] = a
conclusion drawn here.

Set (a): n = 2304, q = 61,275,424,977,257 ≈ 2^45.80, `K_MAX` 4,096. Rules: EIP-8037 / 8038 / 7976 / 2780; regular gas
≤ 2^24 per transaction, total (regular + state) against an Ethereum-like 60 M block; every row a relayed full
transaction with a non-zero absolute fee and a cold implementation.

## What was done

- Part 1: op 1, op 7 M = 4 and op 7 M = 8 (G = 2, today's lanes) through the token at set (a), plus the `ROLL_MAX`
  re-find and prepare-acc [measured; precompile estimate].
- Part 2: two packed stored layouts written as work-tree patches and measured the same way: **P46** (46-bit fields,
  four coefficients = one 64-bit-lane word = 23 bytes) and **P51** (51-bit lanes, five per word, unreduced sums of up
  to 36 terms). Correctness: round trip, all pins at each layout's `ROLL_MAX` (including the lane-overflow check of
  `ROLL_MAX` all-`q − 1` entries), and a differential run of the functional PQZ suites [measured].

## Findings

1. **op 7 M = 8 at set (a), today's lanes [measured + estimate]:** regular 10.54 M (fits 2^24, the precompile may grow
   1.90×), state 62.39 M, total 72.93 M: **over a 60 M block at any precompile price** (its 39,312-byte blob alone
   is 60.3 M of state gas). op 1 (37.72 M) and op 7 M = 4 (38.62 M) fit both limits; `ROLL_MAX` = 96.
2. **P46 saves 8.10 M state gas per op 1, 8.43 M per op 7 M = 4, 16.80 M per op 7 M = 8 [measured]**, exactly the
   blob bytes saved × 1,530, and 15.96 M state + 1.98 M regular per account at prepare (417 `acc` slots instead of
   580), for +0.22–0.29 M regular per debit. op 7 M = 8 then totals 56.42 M (fits 60 M), and two op 1 debits fit one
   60 M block (59.69 M).
3. **The rollover price of P46 [measured]:** a stored entry must be spread back into 64-bit lanes (122,923 gas per
   entry fused, against today's 29,702 lane add). Summing the 23-byte groups unspread into two accumulators with
   46-bit carry gaps (67,083) gives 79,824 per entry and **`ROLL_MAX` 80** (today's lanes 96).
4. **P51 [measured]:** −5.63 M state per op 1, cheaper rollover (`ROLL_MAX` 144), but op 7 M = 8 stays over 60 M
   (61.98 M).
5. **Nothing in the proof system changes [inference]:** calldata `out`, the statement (precompile input) and the
   proofs keep 64-bit `be8` lanes; the token packs into the blob and unpacks into the statement. Off-chain readers of
   blobs and of the hint, `accHash` and `ciphertextHash` change. A packed statement would save ≈ 1 % of the state
   saving and change pqz-stmt, both cores and every prover: not worth it.

## Recommendation [inference; the owner decides]

**P46**: 46-bit stored coefficients (4 per 23 bytes), `acc` slots as `not(stream word)` (no slot can be zero for a
reduced `acc`), the rollover's unspread accumulators. Per op 1 including its credit's rollover share: 37.85 M → 30.00 M
(−20.7 %); per op 7 M = 8 including 8 credits: 73.93 M → 57.64 M (−22.0 %). P51 is the fallback if rollover
throughput outweighs state. Open: M = 8's group count G at set (a) under the O9 hint rule was not re-examined; all
precompile prices are estimates.
