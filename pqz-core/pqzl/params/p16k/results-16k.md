# 16k parameter candidate: results for the owner checkpoint (plan 5h Task 7)

**Status:** measured candidate, 2026-10-21. Nothing in production changed: no header, Rust / C / Solidity constant, id or
vector. Plan Task 8 switches the code after this checkpoint. Plan: `docs/superpowers/plans/2026-10-20-pqz-state-redesign.md`
(D16, D23, D25); spec §6.

**Candidate.** n = 2560 (k = 40), q = 2^50 − 42,310,535 (prime, q ≡ 9 mod 16; owner ruling Q1), Δ = 2^30 − 41,
β_s = 40, β_e = 182, `K_MAX` = 16,384, `e_T + 2^28` in 29 bits, `M_i` < 2^18, carries 15 bits. PQZL and PQZH share q.

**What is measured and what is estimated.**
- Measured (pinned tools): lattice-estimator and DDGR20 β values; the LaZer codegen ranks and its **proof-size
  estimates** (the codegen's own "~ KiB" line, not a proof that was made; today the codegen ran ≈ 4 % above the measured
  v3 proofs); the forge gas of the as-built contracts with the 16k sizes swapped in.
- Estimates, marked [estimate]: the PQZH Ligero proof bounds (the crate's layout model, see §5); the precompile's gas
  at 16k (no calibration in this task: plan Task 9 needs the owner's go-ahead); the op 7 M = 8 transaction totals,
  which add that precompile estimate.

## 1. Headline

| Item | Result | Limit |
|---|---|---|
| Encryption security (key and enc, n = 2560) | uSVP β 508; dual_hybrid β 499 / 500; 2^145.7 / 2^132.7 | β ≥ 450 |
| DDGR20 worst case at 144 hints (one group: 8 legs + auditor) | **β 462.68** | ≥ 450 → **M = 8 uses G = 1** |
| Smallest proof-instance β (all 14 specs, both models) | **455** (MSIS of R_TX / R_TX0 / R_BURN / R_TXM M = 2, M = 4 off); hiding MLWE uSVP ≥ 471, dual_hybrid **462 / 463** | ≥ 450 |
| Largest PQZL codegen proof | **76,002 B** (R_TXM M = 8, G = 2, auditor); G = 1: **60,882 B** | `MAX_PROOF` 98,304 |
| Largest PQZL precompile input | 345,191 B (M = 8, G = 2, auditor); G = 1: 309,591 B | `MAX_INPUT` 512 KiB (also under today's 393,216) |
| `ROLL_MAX` | **208** (relayed 12,564,860 gas; 224 relayed: 13,256,108) | 0.75 · 2^24 = 12,582,912 |
| `mtxPrepareAcc` halves | 7,176,058 direct, 7,213,421 relayed (each) | 12,582,912 |
| op 7 M = 8 transaction, G = 2 | ≈ 20.6 M [estimate] — **does not fit** | 2^24 = 16,777,216 |
| op 7 M = 8 transaction, G = 1 | ≈ 15.4 M [estimate] — fits, ≈ 1.3 M margin | 2^24 |
| n = 2304 at 80 hints | β 415.29 (0 hints: 439.58; key uSVP 440) — **does not clear 450**: no owner checkpoint | ≥ 450 |
| PQZH Ligero proof bound, debit forms | **≈ 302.7 KB [estimate] — over `MAX_PROOF_PQZH` 262,144** (owner) | 262,144 |
| e_s0 checks at 16k (budget, exactness, Fiat–Shamir rounds) | all met | — |

**Decisions the numbers force (O9 rule):**
1. **op 7 M = 8 uses one randomness group (G = 1)**: 144 worst-case hints give β 462.68 ≥ 450 (auditor off, 128 hints:
   467.60). Groups of up to 8 legs share one `(r, e1)`. This is a new relation shape (`txm8g1` / `txm80g1` here),
   and on chain it is also the only M = 8 shape that fits 2^24 (§6). Task 8: `G = ⌈M / 8⌉` (or G = 1 for M ≤ 8) in the
   relation, `pqz-stmt`, both cores and the Solidity layout.
2. **`ROLL_MAX = 208`** (the largest multiple of 16 whose relayed call stays under 0.75 · 2^24).
3. **n = 2304 is out**: below 450 already without hints.
4. **Owner item: PQZH's `MAX_PROOF_PQZH`.** At the 16k sizes every PQZH debit proof bound is ≈ 302 KB (> 262,144 B);
   R_REG / R_DS / R_DR stay at ≈ 233 KB. No other preset in the model's search is meaningfully smaller (§5). Either
   `MAX_PROOF_PQZH` rises (e.g. 320 KiB = 327,680; every PQZH input up to op 7 M = 4 stays ≤ 469,355 B, under 512 KiB)
   or PQZH stays without a 16k id. PQZH op 7 M = 8 stays unbuilt (G = 1 bound ≈ 305 KB, input ≈ 554 KB > 512 KiB).

## 2. Encryption and DDGR20 hints

`enc-16k.txt` (lattice-estimator 53da598, ADPS16, full `LWE.estimate` without arora-gb / bkw / bdd_mitm_hybrid):

| Instance | primal uSVP β | best attack classical / quantum |
|---|---|---|
| n = 2560 key (m = n) | 508 | 2^145.7 / 2^132.7 (dual_hybrid β 499 / 500) |
| n = 2560 enc (m = n + 48) | 508 | 2^145.7 / 2^132.7 (dual_hybrid β 499 / 500) |
| n = 2304 key / enc (β_s 38, β_e 173) | 440 | 2^126.4 / 2^115.3 (dual_hybrid β 433 / 435) |
| Kyber-512 (reference) | 406 | — |

DDGR20 (leaky-LWE-Estimator 0a9caf8; `../anon/hints.sage` rerun at 16k by `run_hints16k.sh`; one shared `(r, e1)`,
m = n + 16; 16 hints per key; "mixed" = worst-case maximal-norm forms, V_max = ½·182² + 10·40² = 32,562):

| hints | unit on r | unit on e1 | mixed (worst) | estimator n − h |
|---|---|---|---|---|
| 0 | 507.31 | 507.31 | 507.31 | 508 |
| 16 | 503.03 | 502.84 | 502.32 | 504 |
| 32 | 498.76 | 498.38 | 497.34 | 499 |
| 48 | 494.50 | 493.92 | 492.36 | 495 |
| 64 | 490.24 | 489.47 | 487.39 | 491 |
| 80 | 485.98 | 485.02 | 482.43 | 486 |
| 96 | 481.74 | 480.59 | 477.48 | 482 |
| 112 | 477.50 | 476.15 | 472.54 | 478 |
| 128 | 473.26 | 471.73 | 467.60 | 474 |
| **144** | 469.03 | 467.31 | **462.68** | 470 |
| 256 | 439.58 | 436.56 | 428.41 | 440 |
| 272 | 435.40 | 432.19 | 423.55 | 436 |

The 0-hint row reproduces spec §6.2's 507.3; 80 hints give 482.43 (spec: 482.4). Largest group with β ≥ 450: 8 legs
(auditor on and off); M = 16 in one group (272 / 256 hints) fails. **n = 2304** (`hints-16k-n2304.txt`): 0 / 80 / 144
hints → 439.58 / 415.29 / 396.01.

## 3. PQZL proof instances (LaZer codegen 3330e48 + lattice-estimator 53da598)

`e_s1_16k.sage` = `../e_s1_proof.sage` plus the dual_hybrid check: `pqz_delta` lowered until MSIS β ≥ 450, `kmlwe_min`
raised until the hiding MLWE has uSVP **and** dual_hybrid β ≥ 450 under both models. Every spec met MSIS at LaZer's
default `pqz_delta = 1.00366`; the codegen's default hiding rank 38 gives dual_hybrid **446 / 447** for every spec, so
**`kmlwe_min = 39`** for all (dual_hybrid 462 / 463). LaZer's λ (Z_q amortisation repetitions) is 4 in every header.
Log `estimator-e-s1-16k.txt`; headers `pqz_<rel>_params.h` by `regen16k.sh` (`codegen-16k.txt`); Rust params by
`../to_rust.py`'s converter in `rust/` (its strict parser accepted every value).

| Relation (spec) | m1 + m2 | bits / bin polys | kmsis / kmlwe | MSIS β (classical / quantum bits) | MLWE uSVP β, dual_hybrid β | knowledge error | codegen proof B | today's codegen B |
|---|---|---|---|---|---|---|---|---|
| R_REG (`reg`) | 80 + 70 | — | 19 / 39 | 458 (2^133.7 / 2^121.4) | 475, 462 / 463 | ≤ 2^−127 | 33,734 | 29,188 |
| R_TX (`tx`) | 181 + 71 | 1,105 / 18 | 20 / 39 | 455 (2^132.9 / 2^120.6) | 473, 462 / 463 | ≤ 2^−127 | 52,624 | 44,638 |
| R_TX0 (`tx0`) | 180 + 71 | 1,105 / 18 | 20 / 39 | 455 (2^132.9 / 2^120.6) | 473, 462 / 463 | ≤ 2^−127 | 52,272 | 44,286 |
| R_BURN (`burn`) | 178 + 71 | 1,041 / 17 | 20 / 39 | 455 (2^132.9 / 2^120.6) | 473, 462 / 463 | ≤ 2^−127 | 51,744 | — |
| R_DS (`ds`) | 81 + 70 | — | 19 / 39 | 458 (2^133.7 / 2^121.4) | 475, 462 / 463 | ≤ 2^−127 | 34,278 | — |
| R_DR (`dr`) | 88 + 70 | 464 / 8 | 19 / 39 | 456 (2^133.2 / 2^120.8) | 475, 462 / 463 | ≤ 2^−127 | 35,142 | — |
| R_TXM M = 2, aud (`txm2`) | 184 + 71 | 1,169 / 19 | 20 / 39 | 455 (2^132.9 / 2^120.6) | 473, 462 / 463 | ≤ 2^−127 | 53,504 | 45,518 |
| R_TXM M = 2, off (`txm20`) | 182 + 71 | 1,169 / 19 | 20 / 39 | 455 (2^132.9 / 2^120.6) | 473, 462 / 463 | ≤ 2^−127 | 52,800 | 44,814 |
| R_TXM M = 4, aud (`txm4`) | 190 + 72 | 1,297 / 21 | 21 / 39 | 464 (2^135.5 / 2^123.0) | 471, 462 / 463 | ≤ 2^−127 | 57,202 | 47,278 |
| R_TXM M = 4, off (`txm40`) | 186 + 71 | 1,297 / 21 | 20 / 39 | 455 (2^132.9 / 2^120.6) | 473, 462 / 463 | ≤ 2^−127 | 53,856 | 45,870 |
| R_TXM M = 8, G = 2, aud (`txm8`) | 282 + 72 | 1,553 / 25 | 21 / 39 | 456 (2^133.2 / 2^120.8) | 471, 462 / 463 | ≤ 2^−127 | 76,002 | 64,578 |
| R_TXM M = 8, G = 2, off (`txm80`) | 274 + 72 | 1,553 / 25 | 21 / 39 | 457 (2^133.4 / 2^121.1) | 471, 462 / 463 | ≤ 2^−127 | 73,026 | 61,634 |
| **R_TXM M = 8, G = 1, aud (`txm8g1`)** | 202 + 72 | 1,553 / 25 | 21 / 39 | 462 (2^134.9 / 2^122.4) | 471, 462 / 463 | ≤ 2^−127 | **60,882** | (new) |
| **R_TXM M = 8, G = 1, off (`txm80g1`)** | 194 + 72 | 1,553 / 25 | 21 / 39 | 463 (2^135.2 / 2^122.7) | 471, 462 / 463 | ≤ 2^−127 | **57,938** | (new) |

MLWE best attack 2^134.9 classical / 2^122.7 quantum (dual_hybrid) for every spec. Every codegen proof is under
`MAX_PROOF` 98,304 (largest 76,002, 77 %); the codegen figure is an expectation, the real proof length varies around
it, so Task 8 measures the maximum from real proofs.

**Statements and inputs** (statement lengths from the pqz-stmt layout at 8 · 2560-byte keys; input = 5 + statement +
codegen proof): R_TX 103,552 → 156,181; R_TX0 82,944; R_BURN 62,336; R_REG 20,576; disclosures 41,376; op 7 M = 4
aud 165,760 → 222,967; M = 8 G = 2 aud 269,184 → **345,191**; M = 8 G = 1 aud 248,704 → **309,591**; M = 8 G = 1 off
227,200 → 285,143. All under `MAX_INPUT` 512 KiB (524,288), and under today's 393,216 too.

## 4. e_s0 at 16k (`e-s0-16k.txt`, `e_s0_16k.py`)

Budget: 15·K = 245,760 < 2^18; K·B_FRESH = 239,599,616 ≤ 2^28; 2E = 2^29 ≤ Δ; Δ(2^18 − 1) + E = 2^48.0 < q/2; mint
margin 3.36×; 64-bit lanes hold 2^64 / q = 2^14 terms ≥ `ROLL_MAX` + 1 + `INLINE_MAX` = 225. Challenge space κ = 8,
η = 137, 2/|C| = 2^−129.78, 2κ < the LS18 bound 2,896. Exactness: b'² + β_e² = 2^37.75 < q; 41·N·b' = 2^37.75 < q;
largest reconstructed integer 2^29 < q; R_DR Δ·15 + 2^29 < q. Fiat–Shamir rounds: JL 128.00, Z_q amortisation
λ = 3 → 150 bits (LaZer's headers use λ = 4: 200 bits), R_q aggregation 800, final challenge 129.78. **Gate met.**

## 5. PQZH Ligero at q = 2^50 − 42,310,535 (`ligero-16k.txt`, `ligero16k.py`) [estimate]

- **Field and domains (exact):** q − 1 = 2^3 · 19 · 43 · 431 · 5,659 · 70,627; 3 is a non-square (F_q^4 = F_q[X]/(X^4 − 3)
  as today) and generates F_q^*. Every radix of today's FFT (2, 19, 43, 431) divides q − 1, so every domain of
  today's crate exists, including THE preset n = 32,756 = 4 · 19 · 431. F_q elements take 7 bytes (today 6).
- **Model:** the crate's `cs::Layout::new` and `Params::max_len_exact` with the widths as parameters (N = 2560, the
  CBD(20) l2 slack 16 bits instead of 15, M 18, carries 15, e_T / e' 29 bits, 7-byte elements); its self-check
  reproduces all 20 pinned bounds of today's crate (`limits_exact`) exactly.
- **THE preset kept** (n = 32,756, k = 817, t = 121, 127.2 bits proven; t depends only on n, k):

| Form | rows today → 16k | proof bound today → 16k B | ≤ 262,144 | input B | ≤ 512 KiB | prover products |
|---|---|---|---|---|---|---|
| R_REG, R_DS, R_DR | 63 → 83 | 190,458 → 233,289 | yes | 253,870 / 274,670 | yes | 1.44e9 |
| R_TX, R_TX0 | 125 / 124 → 165 | 235,470 / 234,744 → 302,743 | **no** | 406,300 / 385,692 | yes | 2.69e9 |
| R_BURN | 124 → 164 | 234,744 → 301,896 | **no** | 364,237 | yes | 2.67e9 |
| R_TXM M = 2 aud / off | 125 → 165 | 235,470 → 302,743 | **no** | 427,036 / 406,300 | yes | 2.69e9 |
| R_TXM M = 4 aud / off | 126 / 125 → 166 / 165 | 236,196 / 235,470 → 303,590 / 302,743 | **no** | 469,355 / 447,516 | yes | 2.70e9 |
| R_TXM M = 8 G = 2 aud (not built) | 188 → 248 | 281,208 → 373,044 | no | 642,233 | no | 3.95e9 |
| R_TXM M = 8 G = 1 aud / off (not built) | — → 168 / 167 | — → 305,284 / 304,437 | no | 553,993 / 531,642 | no | 2.73e9 |

- **Preset search** (proven, radices 2/19/43/431, n ≥ 4k, prover ≤ 4·10^9 products): the smallest R_TX bound is
  301,956 B (n = 37,066, k = 817, t = 120), 0.3 % under THE preset at 18 % more prover work; nothing reaches 262,144.
  The prover budget holds at THE preset (2.7·10^9 products ≤ 4·10^9).

## 6. Gas on the as-built contracts at the 16k sizes (`gas16k.sh`)

`gas16k.sh` copies `smartcontracts/evm`, swaps only the size constants (q, Δ, `PK` 20,480, `CT` 20,608, the lane
constant, `ZERO_HASH`, 644 `acc` words in halves of 322, `K_MAX`, `ROLL_MAX`, payload / disclosure lengths) and runs
the pins of `test/pqz/PqzStateGas.t.sol` (distinct cold blobs, every coefficient q − 1, `ACC_MARK` words, each test
its own transaction). Execution gas of the token call; precompile and ML-DSA mocked. Logs: `gas-16k-r208.txt`
(`ROLL_MAX` = 208, op 7 proof 76,002 B), `gas-16k-r224.txt` (the 224 build), `gas-16k-r208-g1.txt` (`G1=1`: one group
for M ≤ 8, proof 60,882 B), `gas-today-n2048.txt` (the same tests at today's sizes).

| Call | today (n = 2048) | 16k (n = 2560) |
|---|---|---|
| `mtxRollOver` 1 / 16 / 128 | 2,854,442 / 3,430,787 / 7,498,963 | 3,553,051 / 4,232,596 / 9,071,332 |
| `mtxRollOver` `ROLL_MAX` direct / relayed | 256: 12,148,307 / 12,185,595 | **208: 12,527,572 / 12,564,860** |
| `ROLL_MAX` + 16 relayed (own build) | — | 224: 13,256,108 (> 12,582,912) |
| fit: per entry / fixed | 36,323 / 2,849,619 | 43,203 / 3,541,348 |
| `ROLL_MAX` after a TRIVIAL-only rollover | 12,088,219 | 12,467,484 |
| `mtxPrepareAcc` half 0 / 1, direct / relayed | 5,757,946 / 5,795,309 | **7,176,058 / 7,213,421** |
| op 1 BUNDLE, auditor, fresh ref | 4,002,873 | 4,928,464 |
| op 1, materialised `acc`, hint / no hint | 4,133,936 / 5,229,390 | 5,072,798 / 6,433,509 |
| op 7 M = 4, auditor | 4,468,572 | 5,419,746 |
| op 7 M = 8, auditor, G = 2 / G = 1 (2-byte proof) | 8,586,995 / — | 10,484,989 / 6,058,863 |
| burn / refresh | 3,857,681 / 3,832,302 | 4,769,650 / 4,744,270 |
| shield append / merge | 73,940 / 51,774 | 73,940 / 51,774 |

**op 7 M = 8 against the 2^24 transaction gas cap** (direct call; relayed adds ≈ 37 k plus the envelope):

| | today (G = 2) | 16k G = 2 | **16k G = 1** |
|---|---|---|---|
| proof (codegen) | 64,578 | 76,002 | 60,882 |
| calldata bytes | — | 123,428 | 87,812 |
| execution, precompile mocked (measured) | 9,017,286 | 11,081,772 | 6,414,824 |
| calldata EIP-2028 (measured; all-non-zero bound) | 1,453,236 | 1,729,664 (1,974,848) | 1,253,252 (1,404,992) |
| 21,000 + calldata + execution (measured) | 10,491,522 | 12,832,436 | 7,689,076 |
| precompile schedule gas | 6,177,000 (today's row) | ≈ 7.72 M [estimate] | ≈ 7.72 M [estimate] |
| **total** | 16,668,522 (fits by 0.11 M) | **≈ 20.6 M: over 2^24** | **≈ 15.4 M: fits (≈ 1.3 M margin)** [estimate] |

The precompile estimate is today's PQZL op 7 M = 8 row scaled by the statement ratio 1.25 (n 2048 → 2560), applied
to G = 1 too (its statement is 8 % smaller, so this is conservative); input words add ≈ 30 k. G = 2 is over the cap
even with today's unscaled 6.18 M (19.0 M). Task 9's calibration replaces the estimate.

## 7. Files and reruns

All under `pqz-core/pqzl/params/p16k/` (no file in `aprime/` was needed). Tools: LaZer 3330e48,
lattice-estimator 53da598, leaky-LWE-Estimator 0a9caf8, image `sagemath/sagemath@sha256:4f5589eb…` (10.7).

| File | What |
|---|---|
| `<rel>_params.sage` (14) | the 16k specs: reg, tx, tx0, burn, ds, dr, txm2 / 20 / 4 / 40 / 8 / 80, txm8g1, txm80g1 |
| `pqz_<rel>_params.h`, `rust/` | the generated headers (production names) and the `to_rust.py` conversion |
| `e_s1_16k.sage`, `run_e_s1_16k.sh` → `estimator-e-s1-16k.txt` | rank sizing with the dual_hybrid check |
| `regen16k.sh` → `codegen-16k.txt` | the headers and the Rust params |
| `run_hints16k.sh` → `hints-16k-n2560.txt`, `hints-16k-n2304.txt` | `../anon/hints.sage` at 16k (sed of its N, Q, β lines) |
| `enc16k.sage`, `run_enc16k.sh` → `enc-16k.txt` | encryption uSVP and full estimates, n = 2560 and 2304 |
| `e_s0_16k.py`, `run_e_s0_16k.sh` → `e-s0-16k.txt` | budget, exactness, Fiat–Shamir rounds |
| `ligero16k.py` → `ligero-16k.txt` | PQZH domains, proof bounds per form, preset search [estimate] |
| `gas16k.sh` → `gas-16k-*.txt`, `gas-today-n2048.txt` | the as-built gas pins at the 16k sizes |

```sh
T=<dir with lk (0a9caf8), le (53da598), lz (3330e48) checkouts>; P=pqz-core/pqzl/params/p16k
scripts/capped $P/run_hints16k.sh $T/lk $T/le 2560 40 182 > $P/hints-16k-n2560.txt
scripts/capped $P/run_hints16k.sh $T/lk $T/le 2304 38 173 > $P/hints-16k-n2304.txt
scripts/capped $P/run_e_s1_16k.sh $T/lz $T/le reg tx tx0 burn ds dr txm2 txm20 txm4 txm40 txm8 txm80 txm8g1 txm80g1 > $P/estimator-e-s1-16k.txt
scripts/capped $P/regen16k.sh $T/lz > $P/codegen-16k.txt
scripts/capped $P/run_enc16k.sh $T/le > $P/enc-16k.txt
scripts/capped $P/run_e_s0_16k.sh > $P/e-s0-16k.txt
python3 -I $P/ligero16k.py > $P/ligero-16k.txt
PQZ_PROOF_LEN=76002 scripts/capped $P/gas16k.sh <work dir> <smartcontracts/evm/lib> 208 > $P/gas-16k-r208.txt
scripts/capped $P/gas16k.sh <work dir> <lib> 224 --match-test test_gas_rollMax -vv > $P/gas-16k-r224.txt
PQZ_PROOF_LEN=60882 G1=1 scripts/capped $P/gas16k.sh <work dir> <lib> 208 --match-test test_gas_op7 -vv > $P/gas-16k-r208-g1.txt
```
