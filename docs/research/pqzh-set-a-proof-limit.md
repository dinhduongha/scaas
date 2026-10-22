> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH debit proofs at set (a) vs `MAX_PROOF_PQZH` — spikes A and B (research)

Plan 5h Task 8c spike (2026-10-22), branch `pqz-8c-spike` from `pqz-8c` `0189d476`. Research only: the spike code is
labelled throwaway and kept as the record. Raw files: `pqz-core/pqzh/ligero/runs/spike-a-*` and `spike-b-*`. No
wall-clock timing anywhere: work is counted in prover runs and base-field products.

**The problem.** At set (a) (q = 61,275,424,977,257, n = 2304) with THE preset (n 32,756, k 817, t 121), every PQZH debit
form's exact proof bound is 263,784–265,236 B: 1,640–3,092 B above `MAX_PROOF_PQZH` = 262,144, which the owner keeps
(2026-10-21). The precompile's length gate would refuse some honest debit proofs. Options: (A) the prover re-proves until
the proof is ≤ 262,144; (B) a set (a) preset using the radices 7 and 17 of its q − 1; (C) raise the limit (the fallback).

## Spike A: re-prove above the limit

**Method.** `src/bin/spike_retry.rs` (`runs/spike-a.sh`): per debit form, 200 honest proofs with distinct rnd32, each
proved with `spike_prove_attempts(limit = 262,144)` (the same loop as `prove_inner`, at most 16 attempts); every attempt's
length compared with `spike_len_of(query indices)`; the accepted proof verified. Then 10^6 uniform query-index sets
through the same length function (the random-oracle model of the transcript). Log `runs/spike-a-n200.jsonl`.

| form | proofs | prover runs | first attempt min / median / max B | first > limit | max attempts | Monte Carlo P(> limit), 10^6 | expected runs |
|---|---|---|---|---|---|---|---|
| R_TX | 200 | 203 | 258,418 / 261,150 / 262,430 | 3 | 2 | 0.906 % | 1.009 |
| R_TX0 | 200 | 200 | 257,000 / 260,360 / 261,448 | 0 | 1 | 0.0002 % | 1.000 |
| R_BURN | 200 | 200 | 257,992 / 260,328 / 261,672 | 0 | 1 | 0.0002 % | 1.000 |
| op 7 M = 2, auditor | 200 | 202 | 258,514 / 261,150 / 262,558 | 2 | 2 | 0.906 % | 1.009 |
| op 7 M = 2, no auditor | 200 | 202 | 257,260 / 261,182 / 262,206 | 2 | 2 | 0.906 % | 1.009 |
| **op 7 M = 4, auditor** | 200 | **286** | 259,132 / 261,876 / 263,092 | **62** | **7** | **27.6 %** | **1.382** |
| op 7 M = 4, no auditor | 200 | 201 | 258,162 / 261,118 / 262,174 | 1 | 2 | 0.906 % | 1.009 |

Every accepted proof (1,400) is ≤ 262,144 (largest 262,142) and verifies. 1,494 / 1,494 prover runs have exactly the
length `spike_len_of` computes from their query indices. With the 16-attempt cap, op 7 M = 4 auditor fails with
probability 0.276^16 ≈ 1.2 · 10^−9 per proof (raising the cap to 32 makes it ≈ 10^−18).

### What the proof length depends on (code reading, confirmed by the runs)

The proof is `root (32) ‖ w, q, h (fixed: 2(2k−1) + (2k−1−l) F_q^4 values) ‖ nonce (8) ‖ for each distinct opened
column in increasing order: salt (32) and m + 12 field elements ‖ the pruned multiproof (32 B per digest)`
(`ligero.rs` `prove_once`). Only two terms vary: the number of distinct indices |I| and the multiproof digest count,
which `merkle.rs` `Tree::multiproof` derives from the sorted index set alone (a sibling is sent when it is not itself on
a path). I = the t draws `Tr::index(n)` of the Fiat–Shamir transcript after absorbing the statement, the root, w, q,
h and the nonce. **Nothing witness-dependent enters the length except through I**, and I is a random-oracle output.

### Zero knowledge of rejection on length

Let P be the honest prover's output distribution on (x, w) and S the zero-knowledge simulator (programming the random
oracle; pqzh-ligero.md §4.1), with P and S ε-indistinguishable. The limited prover outputs P conditioned on the event
E = {len(π) ≤ L}: its attempts are independent honest proofs (fresh masks and salts from the continued SHAKE256 stream,
so fresh roots and fresh oracle inputs). E is a predicate of the public proof alone. The simulator S_L runs S until its
output is in E. Then:

- the output distributions are P|E and S|E, and SD(P|E, S|E) ≤ 2 ε / Pr_P[E] (conditioning on an event amplifies the
  distance by at most 1 / Pr[E]); Pr[E] ≥ 0.72 for every form, so ≤ 2.8 ε;
- Pr[E] does not depend on the witness: in the random-oracle model I is uniform and independent of everything the prover
  chose, so the number of attempts, the work and any retry an observer sees carry no information about w (measured: the
  real first-attempt rates 1.5 % / 31 % match the uniform-index Monte Carlo 0.9 % / 27.6 % within sampling error);
- the cap's failure (no proof after 16 attempts) is likewise a witness-independent event;
- soundness is untouched: the verifier and its bound do not change (a cheating prover could always grind its proofs).

This answers pqzh-ligero.md §12 review finding 6 ("the retry would bias the distribution the simulator has to match"):
the bias is conditioning on a public event, which the simulator reproduces by rejection. **A survives.**

### Cost to make A production

`prove` uses the limit min(bound, `MAX_PROOF_PQZH`) (no-op at v3, whose bounds are all below; v3 proofs stay
byte-identical), the attempt cap raised to 32, the argument above in pqzh-ligero.md, a test. A few lines; half a day
with the review. Cost at runtime: +38 % prover runs on average for op 7 M = 4 with the auditor (up to 7 runs seen),
+0.9 % for R_TX / op 7 M = 2 / M = 4 without the auditor, none for R_TX0 / R_BURN. The verifier is unchanged. Sizes
unchanged: debit proofs sit at 257–262 KB, right under the limit.

## Spike B: radices 7 / 17 and their preset

**Method.** Feature `spike-b`: set (a)'s `pqzh_set_spike_b.rs` with radices [2, 7, 17, 19, 43, 431] and the preset of
`ligero_params.py --set n2304-kmax4096`'s search: n = 45,752 = 2^3·7·19·43 (code on the coset 3·H_n), k = 952 =
2^3·7·17, t = 119, l = 832, products on H_2261 (2261 = 7·17·19). `fft.rs` takes the radices as a slice; **no new FFT
code**: radices 7 and 17 run through the existing generic r-point DFT stage (radix 2 keeps its butterfly). A product
counter (feature `spike-count`) counts base-field products of prover and verifier. `runs/spike-b.sh` + `ct.sh`.

**Results.**

| check | result |
|---|---|
| tests (`spike-b-tests.txt`) | 15 + 16 (+ `evm_fixtures` ignored) + 8 + 1 pass, production 13; the FFT test adds sizes 7, 17, 14, 119, 952, 2261, 45,752 against the naive DFT; two pins changed: `limits_exact` (the new bounds) and `transfer_forms_cross_rejected` (R_TX0 and R_TX now have the same 124 rows, so equal bounds) |
| `max_len_exact` exactness | still exact, but the test's left-spread index set reaches worst − 1 digest at n = 45,752; the right-spread set reaches it (test changed to take the larger) |
| completeness | 24 / 24 honest proofs verify (`spike-b-kat.jsonl`) |
| native = wasm32 | 24 / 24 identical, 144 / 144 mutations rejected (`spike-b-native-vs-wasm.txt`): the wasm32 build needs nothing new |
| constant time (`ct-spike-b.txt`) | 0 secret-dependent reports, every proof verifies |
| soundness (crate, `spike-b-sizes.jsonl`) | query 128.00 bits (t = 119 is the model's minimum), proximity ≥ 159.7, linear ≥ 169.3, quadratic 183.2, Keccak 128; **total 127.00** vs 127.23 at THE preset. t = 120 gives query 128.94, total ≈ 127.5 [model] |

| form | rows m (B / THE) | bound B, t = 119 [crate] | bound t = 120 [model] | bound THE preset | honest proofs B | tx calldata B (bound) |
|---|---|---|---|---|---|---|
| R_REG, R_DS, R_DR | 63 / 83 | 206,958 | 207,688 | 204,978 | 203,148–204,206 | — |
| R_TX, R_TX0, R_BURN, op 7 M = 1 | 124 / 164–165 | **250,512** | 251,608 | 263,784–264,510 | 245,296–248,048 | ≈ 273.6–273.8 K |
| op 7 M = 2 / M = 4, auditor | 125 / 165; 126 / 166 | 251,226 / **251,940** | — / 253,048 | 264,510 / 265,236 | 247,172–249,348 | ≈ 276.2 K (M = 4) |

All built debit bounds are 10.2–11.6 KB under 262,144 (no retry, no new argument). The input of op 7 M = 4 with the
auditor (401,321 B) is above today's `MAX_INPUT` 393,216 (fits 8d's 512 KiB). Debits still cannot ride one 2^24
transaction: the calldata stays ≈ 274–276 KB > 261,909 (floor ≈ 17.5–17.7 M instead of 18.4–18.5 M).

**Work (base-field products, seed 0, `spike-b-count*.jsonl`).** Prover: debits 2.33–2.39 · 10^8 vs 2.44–2.49 · 10^8
at THE preset (−4 to −5 %), R_REG / R_DS / R_DR −3 %. Verifier: 0.97–1.04×. **The model's "≈ 5× fewer prover
products" was wrong**: `ligero_params.py` charges every FFT point (r + 1) products per stage, but the crate's deepest
stage skips the zero padding (k message values on n points), so the radix-431 stage is cheap in practice.

### Cost to make B production

Small, because the FFT is unchanged: `pqzh_set.rs` of set (a) gets the six radices and the new preset (t = 119 or 120,
an owner choice on the soundness total), `fft.rs`'s radices as a slice (done in the spike), the tests (the two pins
above, FFT sizes), `ligero_params.py` / PQZH.md numbers, the 8b generator writing the preset. Review surface: the new
domains (smoothness, the coset 3·H_45,752 missing H_952: tested), the per-set preset (each set's id fixes its
parameters, already the rule), the soundness accounting at t = 119 / 120, the exactness of `max_len_exact` at a
non-power-of-two n (now tested with both spreads). About a day with the review; plus a wasm32 verify timing before any
chain uses it (the verifier does the same work within ±4 %).

## Comparison and recommendation

| | A: re-prove above 262,144 | B: radices 7 / 17 preset | C: raise `MAX_PROOF_PQZH` |
|---|---|---|---|
| debit proofs | 257–262 KB, bound unchanged (263.8–265.2 KB) | 245–249 KB honest, bound 250.5–251.9 KB (t = 119) | as today, 259–262 KB honest |
| margin under 262,144 | none (rejection keeps it under) | 10.2–11.6 KB (9.1 KB at t = 120) | n/a (limit ≥ 265,236) |
| prover work | +38 % average on op 7 M = 4 auditor, ≤ +1 % elsewhere; a 10^−9 (cap 16) failure tail | −4 to −5 % | none |
| verifier | unchanged | ±4 % products, larger domain table (n 45,752) | unchanged |
| code | a few lines in `prove` + cap | per-set radices / preset (≈ 40 lines, spike done) | one constant (+ pqz-stmt / node / docs) |
| crypto argument | the conditioning argument above (new, short) | parameters only; soundness total 127.00 at t = 119 (< 127.23) or ≈ 127.5 at t = 120 | none |
| risk | a retry path in the prover; prover-side only | new domains and a set-specific preset (tested: FFT vs naive, native = wasm32, constant time) | contradicts the owner's ruling; bigger inputs |
| one 2^24 tx for a debit | no | no | no |

**Recommendation [inference; the owner decides]: B with t = 120.** It brings every set (a) PQZH proof ≈ 9–10 KB under
the limit with no protocol change, no new zero-knowledge argument and no prover penalty; the feared FFT work did not
materialise (the generic stage handles 7 and 17, wasm32 and the constant-time check pass unchanged). t = 120 keeps the
soundness total above today's 127.23. A is the cheap fallback if a set-specific preset is unwanted (its argument
holds, its cost is +38 % prover runs on op 7 M = 4 with the auditor). C stays the fallback of last resort. None of
them lets a PQZH debit fit one 2^24 transaction at set (a).

## Decision and fallbacks (owner 2026-10-22)

**B shipped at t = 120** (owner 2026-10-22: "chọn B, A và C là các phương án dự phòng"; plan 5h Task 8c part 1b, branch
`pqz-8c`): set (a)'s `pqz-core/params/sets/n2304-kmax4096/pqzh_set.rs` holds radices 2 / 7 / 17 / 19 / 43 / 431 and the
preset n 45,752, k 952, **t 120** (l 831, products on H_2261). Built and measured [crate, `runs/c8b-a-sizes.jsonl`,
equal to `ligero_params.py --set n2304-kmax4096`]: R_REG / R_DS / R_DR 207,688; R_TX / R_TX0 / R_BURN / op 7 M = 1
251,608; op 7 M = 2 auditor 252,328; op 7 M = 4 auditor **253,048** (9,096 B under 262,144; input 402,429); soundness
query 128.94, total **127.40** bits on every relation (THE preset 127.23). Debit calldata at the bound 274.7–277.3 KB:
still no 2^24 transaction (set (a) `PQZH.md`). Part 1b's round (tests, native = wasm32, constant time, product counts):
`pqz-core/pqzh/ligero/runs/c8b-*`. Product counts at t = 120: prover debits 2.34–2.39 · 10^8 vs 2.44–2.49 · 10^8 at
THE preset (−4 to −5 %), verifier 0.97–1.04×. `ligero_params.py --set` now counts the prover's FFT products as `fft.rs`
does (zero-padding skip of the deepest stage): model / crate 0.93–0.96 (`runs/c8-params-n2304-kmax4096.txt`), which
replaces the per-point charge behind the earlier "5×" claim.

The two other options are kept as fallbacks; neither is in a production build.

- **A — re-prove under `MAX_PROOF_PQZH`** (fallback; Cargo feature `fallback-retry` of `pqzh-ligero`, set (a) only,
  never in the default or production builds): THE preset (n 32,756, k 817, t 121, radices 2 / 19 / 43 / 431; constants
  in `pqzh_set_fallback.rs`), the prover's length limit min(verifier bound, 262,144) (`ligero.rs` `prover_limit`) and
  up to 32 attempts (failure ≈ 0.276^32 ≈ 10^−18 per op 7 M = 4 auditor proof). The verifier and its bounds
  (263,784–265,236) are unchanged; every accepted proof is ≤ 262,144. Costs: +38 % prover runs on average on op 7 M = 4
  with the auditor, ≈ +0.9 % on R_TX / op 7 M = 2 / M = 4 without the auditor (spike A). Zero knowledge: the section
  "Zero knowledge of rejection on length" above. When: a chain or reviewer wants no set-specific preset. The spike's
  code is also tagged `pqzh-set-a-fallback-A` (local tag on `4f3477b8`).
- **C — raise `MAX_PROOF_PQZH` for set (a)** (fallback of last resort; documented only, no code): with THE preset,
  `MAX_PROOF_PQZH` ≥ 265,236 (the op 7 M = 4 auditor bound) as one per-set constant (pqz-stmt, the precompile, the node
  and the docs that quote it). It contradicts the owner's 2026-10-21 ruling that the limit stays, so it is used only when
  neither B nor A is acceptable. Inputs grow with it (op 7 M = 4 auditor 414,617 B, above today's `MAX_INPUT` 393,216;
  fits Task 8d's 512 KiB).

The 16k set (`n2560-kmax16384`) has the same problem without B: its q − 1 = 2^3·19·43·431·5,659·70,627 has no other
small radix, and the preset search with the corrected prover-cost model finds no proven preset with a debit bound below
≈ 299.6 KB (n up to 148,264) [model]. A cannot bridge a gap of ≈ 37–41 KB either (at set (a) with THE preset, honest
debit proofs sit ≈ 2–7 KB under their bound [measured, spike A]), so only C or "no PQZH debits at 16k" remain on today's
numbers. The question is open for the owner when the 16k set is built (16k `PQZH.md`); not decided here.
