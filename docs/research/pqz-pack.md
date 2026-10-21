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

## Discussion and decision (owner and controller, 2026-10-21)

**Why M = 8 was first ruled out, and why that was wrong.** The SCaaS testnet move to Amsterdam measured the precompile
input sent *directly* as calldata (statement + proof ≈ 278–310 KB) against the EIP-7976 floor limit of 261,909 B per
transaction, and op 7 was ruled to M ≤ 4. Through the token the precompile input is built in memory from state (keys from
the registry, `acc` and pending entries from the contract); the relayed calldata is only the payload and the proof
(op 7 M = 8, G = 2: ≈ 124 KB at 16k, Task 7 table). The ruling was withdrawn; M = 8 is bounded by block gas, not calldata
(Finding 1).

**SSTORE and SSTORE2 under Amsterdam [measured / from the Glamsterdam gas-impact note of the Nethermind 2.2.0 move].**

| Store | First write | Overwrite | Used for |
|---|---|---|---|
| SSTORE (32-byte slot) | 97,920 state gas per new slot (≈ 3,060 / byte) | 10,000 regular gas (EIP-8038, ≈ 312 / byte) | `acc` (580 words at set (a), 417 under P46), counters, `accHash` — data rewritten in place |
| SSTORE2 (contract code) | ≈ 1,530 state gas / byte (EIP-8037) | not possible (immutable) | op blobs — written once, never changed |

Both choices of today's design are the cheaper store for their data: an `acc` in SSTORE2 would re-deploy ≈ 28 M of state
gas at every rollover; a blob in slots would cost twice the state gas. The bytes stored are what P46 reduces. The blob
is dominated by the shared `u` (2,304 coefficients); `v` is 16 coefficients (128 B) per recipient, and one `u` per
randomness group is already shared by every leg (CTR-PQZ-04). Further options not taken: Kyber-style compression of `u`
(adds noise to every homomorphic sum, `K_MAX` 4,096 of them — a parameter study), dropping the auditor copies from state
(rejected: they are ciphertexts too), G = 1 for M = 8 (≈ 449 at 144 hints at set (a) [inference], below 450).

**Ciphertexts stay in state — absolute (owner 2026-10-21: "Không được mất ciphertext").** A hash-only design (blob
bytes in calldata / events, the hash in state) was considered and rejected: calldata and logs live in block history,
which clients prune (EIP-4444 history expiry), and a lost ciphertext freezes its funds for good. The state-gas cost is
accepted as the price of that rule.

**No zero-gas assumption (owner 2026-10-21: the precompile may be deployed for customers).** Costs are real money on a
customer chain. On 2026-10-21 (public RPC + CoinGecko): Ethereum 0.041 gwei, ETH $2,454; BSC 0.05 gwei, BNB $747 — 30 M
gas ≈ $3.0 on Ethereum, ≈ $1.12 on BSC; at 1 gwei ≈ $74 on Ethereum. (Mainnet Ethereum and BSC had not activated
Glamsterdam; under their rules a 20 KB SSTORE2 blob is ≈ 4.2 M gas.)

**Why a 60 M block, and the outlook.** 60 M is Ethereum mainnet's block gas limit on 2026-10-21 (read over RPC), used as
the "customer-like" yardstick instead of the testnet's 200 M target; it is not a protocol constant (operators choose it,
±1/1024 per block). Reported plans: Sepolia raised to 200 M with Glamsterdam (October 2026), Hoodi activates Glamsterdam
on 2026-10-26 with 200 M, mainnet date open, 300 M floated as a later step (news coverage of the Ethereum Foundation
announcement — [CCN](https://www.ccn.com/news/crypto/ethereum-glamsterdam-upgrade-testnet-200m-gas-limit/),
[U.Today](https://u.today/ethereum-eyes-massive-33x-gas-limit-boost-as-glamsterdam-approaches),
[FinanceFeeds](https://financefeeds.com/ethereum-schedules-glamsterdam-upgrade-on-hoodi-for-october-26-targeting-200-million-gas-limit/);
no primary EF page read). Larger blocks cost node processing time, state growth (which EIP-8037 prices on purpose),
sync time and hardware; 200 M blocks were not load-rehearsed on the SCaaS testnet. With 200 M blocks every layout fits
M = 8, so cost decides, not block fit.

**Cost per credit, P46 vs P51 [inference from the measured numbers].** A rollover is ≈ 12.5 M regular gas, so per credit
≈ 156 k under P46 (`ROLL_MAX` 80) and ≈ 87 k under P51 (`ROLL_MAX` 144); P46 saves ≈ 2.5 M more state gas per op than
P51. P46 is cheaper overall by a wide margin.

**Decision (owner 2026-10-21): P46.** Built in 5h Task 8d with the proofSystemId bump: stored blob and `acc` layout,
hint format, `accHash`, `ciphertextHash`; the token unpacks to 64-bit lanes for the precompile, so pqz-stmt, the
precompile and the proofs do not change; the packed rollover accumulator; `ROLL_MAX` re-measured (≈ 80 at set (a));
the disclosure and hint paths measured and tested there. Each parameter set's `SET.md` states the condition "op 7 M = 8
needs a block gas limit ≥ ≈ 57 M" (P46).
