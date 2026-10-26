# Smaller ring dimension n for PQZ: results (plan 5h Task 7c, research)

**Status:** research, 2026-10-21. Owner request 2026-10-21: "Cân nhắc theo hướng giảm n. Tìm hiểu xem." Nothing in
production or in the approved 16k set changed; this directory only adds scripts, logs and this file. Research is not a
decision: §7 recommends, the owner decides.

**Baseline (approved 16k set).** n = 2560 (k = 40), q = 2^50 − 42,310,535, Δ = 2^30 − 41, `K_MAX` 16,384, mint margin
3.36×; DDGR20 β 507.31 / 497.34 / **482.43** at 0 / 32 / 80 worst-case hints (`../p16k/`).

**Tags.** [measured] = a pinned tool's output in a log here (lattice-estimator 53da598, leaky-LWE-Estimator 0a9caf8,
LaZer 3330e48 codegen, image `sagemath/sagemath@sha256:4f5589eb…` = 10.7); [estimate] = a model on measured numbers
(gas, precompile); [inference] = a conclusion drawn here.

## 1. Headline

| | A: n = 2560, K 16,384 (approved) | **B: n = 2432, K 16,384** | **C: n = 2432, K 8,192** | **D: n = 2304, K 8,192** | **E: n = 2304, K 4,096** | **F: n = 2176, K 4,096** | **G: n = 2048, K 1,024** |
|---|---|---|---|---|---|---|---|
| q (smallest admissible prime, mint margin ≥ 3.08×) | 2^50.00 (3.36×) | 2^49.85 | 2^47.85 | 2^47.80 | 2^45.80 | 2^45.75 | 2^41.69 |
| DDGR20 β at 0 / 32 / 80 hints [measured] | 507.3 / 497.3 / **482.4** | 475.2 / 465.3 / **450.5** | 502.5 / 492.0 / **476.4** | 467.7 / 457.4 / **441.9** | 495.8 / 484.8 / **468.5** | 459.6 / 448.7 / **432.6** | 480.6 / 468.5 / **450.5** |
| dual_hybrid at 80 hints − DDGR20 offset, cl. / qu. [estimate] | 474.4 / 476.4 | 442.5 / 443.5 | 466.4 / 469.4 | 434.9 / 434.9 | 458.5 / 461.5 | 424.6 / 427.6 | 442.5 / 442.5 |
| encryption without hints: uSVP, dual_hybrid cl. / qu. [measured] | 508, 499 / 500 | 476, 467 / 469 | 503, 494 / 494 | 468, 459 / 461 | 496, 487 / 489 | 460, 451 / 453 | 481, 471 / 474 |
| keys / ciphertexts / acc words vs 16k | — | −5.0 % | −5.0 % | −9.9 % | −9.9 % | −14.9 % | −19.9 % |
| R_TX / op 7 M = 4 codegen proof [measured] | 52,624 / 57,202 | 51,376 / 55,898 | 50,706 / 55,028 | 49,298 / 53,556 | 48,724 / 52,950 | 47,316 / 51,478 | 44,712 / 47,352 |
| largest PQZL input (op 7 M = 4 auditor) vs `MAX_INPUT` 261,120 | 222,967 | 213,471 | 212,601 | 202,937 | 202,331 | 192,667 | 180,349 |
| `ROLL_MAX`, Amsterdam (regular gas) [estimate] | 80 (7b measured) | 80 | 80 | 96 | 96 | 112 | 128 |
| `ROLL_MAX`, old rules [estimate] | 192 (measured) | 208 | 208 | 224 | 224 | 240 | 256 |
| rollovers to fill `acc` (Amsterdam) | 205 | 205 | 103 | 86 | 43 | 37 | 8 |
| op 1 blob state gas, Amsterdam (EIP-8037) [estimate] | 32.0 M | 30.4 M | 30.4 M | 28.9 M | 28.9 M | 27.3 M | 25.7 M |
| below 450 at 80 hints? DDGR20 / dual_hybrid − offset | no / no | no (450.5) / **yes (442.5)** | no / no | **yes / yes** | no / no | **yes / yes** | no (450.5) / **yes (442.5)** |

Both models cleared 450 at 80 hints only for the approved set and for C (2432 / 8,192) and E (2304 / 4,096); B and G pass
the DDGR20 rule by 0.5 but not the dual_hybrid view that Task 7 applied to the O9 (144-hint) ruling.

**The lever is `K_MAX`, not n alone [measured].** Each doubling of `K_MAX` adds one digit-sum bit (m) and one noise bit
(E), so q grows by 2 bits and β at 80 hints falls by ≈ 24–31; each −128 of n costs ≈ 32–40 β at the same `K_MAX`. At the
approved `K_MAX` 16,384 the only smaller n that keeps β ≥ 450 is **2432 (−5 %), with 0.5 β to spare**; −10 % needs
`K_MAX` 4,096 (or 8,192 with an exception at 441.9), −15 % needs 4,096 with an exception (432.6) or 1,024, and −20 %
(n = 2048, today's n) needs `K_MAX` 1,024 (today's cap) — it then clears 450 by 0.5 because q3 = 2^41.69 is 0.3 bit
below today's 2^42 (mint margin 3.08× instead of 4.14×; today's set is at 446.0). Under the dual_hybrid view on the
hinted instance (Task 7's second model) only C and E of the smaller sets clear 450 (§3.3).

## 2. Method and order of work

1. `budget.py` (stdlib) → `budget.txt`, `cells.json`: the §6.1 budget for every grid cell (n ∈ {2048, 2176, 2304, 2432,
   2560} × `K_MAX` ∈ {1,024, 4,096, 8,192, 16,384}), two primes per cell, the stdlib uSVP shortcut of `../anon/usvp.py`
   (hints as removed dimensions). Prime rule (spec §6.5): q ≡ 9 mod 16, 2^3·19·43·431 | q − 1 (q = 1 + 2,817,016·t,
   t odd), Miller–Rabin with the 12 smallest prime bases.
   - **q3** = the smallest admissible prime whose budget holds with mint margin ≥ 3.08× (the lowest margin the owner has
     accepted, O3; 16k has 3.36×, today 4.14×). The primary candidate everywhere below.
   - **q1** = the smallest admissible prime at all (2E ≤ Δ; margin then 1.12–1.38×), to price the margin in β.
2. `screen.sage` → `screen.txt` (all 41 rows: 20 cells × q3 / q1 + the 16k calibration row): lattice-estimator primal
   uSVP on the encryption instance (m = n + 48) and DDGR20 worst-case mixed hints at 0 / 32 / 80 (`../aprime/aprime.sage`'s
   `ddgr`, unchanged). The calibration row reproduces Task 7 exactly (507.31 / 497.34 / 482.43).
3. Promising cells (β at 80 hints ≥ ≈ 420 and the smallest n per `K_MAX` on either side of 450): six cells, q3 only.
   - `gen_specs.py` → `specs/n<n>k<K>/*_params.sage` (the 16k shapes with the cell's k, β_s / β_e, bit widths; op 7
     M ≤ 4, one group), `e_s1_n.sage` (= `../p16k/e_s1_16k.sage`: MSIS β ≥ 450 by `pqz_delta`, hiding MLWE uSVP **and**
     dual_hybrid β ≥ 450 both models by `kmlwe_min`) → `e-s1-n<n>k<K>.txt`, proof sizes = LaZer codegen estimates;
   - `enc_n.sage` → `enc-n.txt`: full `LWE.estimate` both models, and dual_hybrid on the 80-hint instance minus the DDGR20
     offset (as Task 7's `dual_hints16k.sage`);
   - `e_s0_n.py` → `e-s0-n.txt`: budget, challenge space, exactness, Fiat–Shamir rounds per cell.
4. `sizes.py` → `sizes.txt`: sizes from the pqz-stmt layout, gas models.

**Skipped and why.** q1 rows: screened only (no proof / codegen run): they change only q, and §4 shows what they buy.
Cells with β(80) < 420 (2048 × {4,096, 8,192, 16,384}, 2176 × {8,192, 16,384}, 2304 × 16,384) and cells that are not
the smallest n for their `K_MAX` (2176 / 2304 / 2432 / 2560 × 1,024, 2560 × 4,096 / 8,192): screened only; their
proof sizes lie between the measured neighbours [inference]. Full `LWE.estimate` on the key instance (m = n): every
earlier run gave the same β as the encryption instance (`../p16k/enc-16k.txt`, `../aprime/aprime.txt`). PQZH (backup
only, not on chain): not re-run; q ≤ 2^48 would bring its field elements back to 6 bytes [inference]. No timing runs.

**Tool note (LaZer `log2q`).** The codegen sizes `kmsis` at 2^`log2q` and then requires the exact q to pass the same
root-Hermite test in its `D` loop; with q = 2^47.80 and `log2q` = 48 that loop never ended (the first run of
`n2304k8192` hung in `get_delta_msis`, traced with faulthandler and stopped). `gen_specs.py` therefore rounds `log2q`
down unless q is within 0.01 bit below a power of two (16k and today: 50 and 42, unchanged). Rounding down sizes `kmsis`
against a smaller modulus, i.e. conservatively: at n = 2432 / K 16,384 the R_TX proof is 51,376 B with `log2q` 49
against 51,216 B with 50 (first run, `kmsis` equal, +0.3 %); the MSIS β is re-checked with the exact q either way.

## 3. Security

### 3.1 Budget and q per cell (`budget.txt`) [measured]

| n \ K_MAX | 1,024 | 4,096 | 8,192 | 16,384 |
|---|---|---|---|---|
| bits m / log2 E | 14 / 24 | 16 / 26 | 17 / 27 | 18 / 28 |
| q3, every n | 2^41.69–2^41.91 | 2^45.69–2^45.91 | 2^47.69–2^47.91 | 2^49.69–2^49.91 |
| q1 (margin 1.12–1.38×), every n | 2^41.00 | 2^45.00 | 2^47.00 | 2^49.00 |

β_s / β_e: 36 / 164 (2048), 37 / 169 (2176), 38 / 173 (2304), 39 / 177 (2432), 40 / 182 (2560). Every q3 / q1 has
λ = ⌈128 / log2 q⌉ ≤ 4 (LaZer uses 4) and 64-bit lanes ≥ 2^14 terms.

### 3.2 DDGR20 worst-case mixed hints, 0 / 32 / **80** (`screen.txt`) [measured]

q3 (mint margin 3.08×):

| n \ K_MAX | 1,024 | 4,096 | 8,192 | 16,384 |
|---|---|---|---|---|
| 2048 | 480.62 / 468.53 / **450.47** | 423.79 / 413.09 / **397.11** | 399.18 / 389.08 / **374.00** | 376.70 / 367.14 / **352.87** |
| 2176 | 520.35 / 508.12 / **489.86** | 459.56 / 448.73 / **432.57** | 433.23 / 423.00 / **407.73** | 409.16 / 399.48 / **385.02** |
| 2304 | 560.55 / 548.19 / **529.72** | 495.77 / 484.82 / **468.47** | 467.69 / 457.35 / **441.90** | 442.02 / 432.22 / **417.60** |
| 2432 | 601.08 / 588.60 / **569.96** | 532.31 / 521.25 / **504.73** | 502.48 / 492.03 / **476.42** | 475.20 / 465.30 / **450.51** |
| 2560 | 641.82 / 629.23 / **610.41** | 569.07 / 557.90 / **541.22** | 537.49 / 526.94 / **511.17** | 508.60 / 498.60 / **483.66** |

q1 (mint margin 1.12–1.38×):

| n \ K_MAX | 1,024 | 4,096 | 8,192 | 16,384 |
|---|---|---|---|---|
| 2048 | 491.64 / 479.27 / **460.81** | 432.85 / 421.93 / **405.62** | 407.44 / 397.14 / **381.76** | 384.26 / 374.52 / **359.97** |
| 2176 | 533.13 / 520.60 / **501.89** | 470.08 / 459.01 / **442.48** | 442.82 / 432.37 / **416.78** | 417.93 / 408.05 / **393.30** |
| 2304 | 575.10 / 562.42 / **543.47** | 507.75 / 496.55 / **479.81** | 478.62 / 468.05 / **452.25** | 452.02 / 442.02 / **427.07** |
| 2432 | 617.51 / 604.69 / **585.53** | 545.86 / 534.52 / **517.58** | 514.84 / 504.14 / **488.15** | 486.52 / 476.39 / **461.26** |
| 2560 | 660.35 / 647.39 / **628.03** | 584.36 / 572.89 / **555.76** | 551.45 / 540.63 / **524.45** | 521.38 / 511.14 / **495.83** |

Calibration: the approved 16k prime (2^50 − 42,310,535) gives 507.31 / 497.34 / 482.43 (Task 7: same). The encryption
uSVP β of every row is in `screen.txt` (it equals ⌈DDGR20 h0⌉ within 1).

### 3.3 Full estimates and dual_hybrid at 80 hints (`enc-n.txt`) [measured; the "− offset" column is an estimate]

| row | n | K_MAX | variant | log2 q | best classical / quantum | uSVP | dual_hybrid cl. / qu. | n-80: primal, dual_hybrid cl. / qu. | DDGR20 h80 | offset | dual_hybrid h80 - offset cl. / qu. |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 16k ref (Task 7) | 2560 | 16,384 | 16k | 50.000 | 2^145.7 / 2^132.7 (dual_hybrid) | 508 | 499 / 500 | 486, 478 / 480 | 482.43 | 3.57 | 474.43 / 476.43 |
| 0 | 2048 | 1,024 | q3 | 41.691 | 2^137.5 (dual_hybrid) / 2^125.6 (dual_hybrid) | 481 | 471 / 474 | 456, 448 / 448 | 450.47 | 5.53 | 442.47 / 442.47 |
| 10 | 2176 | 4,096 | q3 | 45.750 | 2^131.9 (dual_hybrid) / 2^120.1 (dual_hybrid) | 460 | 451 / 453 | 437, 429 / 432 | 432.57 | 4.43 | 424.57 / 427.57 |
| 18 | 2304 | 4,096 | q3 | 45.800 | 2^142.2 (dual_hybrid) / 2^129.6 (dual_hybrid) | 496 | 487 / 489 | 473, 463 / 466 | 468.47 | 4.53 | 458.47 / 461.47 |
| 20 | 2304 | 8,192 | q3 | 47.800 | 2^134.3 (dual_hybrid) / 2^122.2 (dual_hybrid) | 468 | 459 / 461 | 446, 439 / 439 | 441.90 | 4.10 | 434.90 / 434.90 |
| 28 | 2432 | 8,192 | q3 | 47.851 | 2^144.2 (dual_hybrid) / 2^131.3 (dual_hybrid) | 503 | 494 / 494 | 481, 471 / 474 | 476.42 | 4.58 | 466.42 / 469.42 |
| 30 | 2432 | 16,384 | q3 | 49.851 | 2^136.4 (dual_hybrid) / 2^124.3 (dual_hybrid) | 476 | 467 / 469 | 455, 447 / 448 | 450.51 | 4.49 | 442.51 / 443.51 |

### 3.4 Proof instances (`e-s1-*.txt`) [measured]

`kmlwe_min` falls with q (16k: 39; K 8,192: 37; K 4,096: 36; K 1,024: 33, today's rank) and `kmsis` rises by 1–3, so the
codegen proofs shrink only 2–17 %. Every spec of every candidate meets MSIS β ≥ 450 at LaZer's default `pqz_delta`
1.00366 and the hiding MLWE uSVP / dual_hybrid β ≥ 450 under both models:

| n / K_MAX | kmlwe_min | kmsis | MSIS β min | MLWE uSVP min, dual_hybrid cl. / qu. | proofs reg / tx / tx0 / burn / ds / dr / txm2 / txm20 / txm4 / txm40 (B) |
|---|---|---|---|---|---|
| 2560 / 16,384 (Task 7) | 39 | 19–21 | 455 | 471, 462 / 463 | 33,734 / 52,624 / 52,272 / 51,744 / 34,278 / 35,142 / 53,504 / 52,800 / 57,202 / 53,856 |
| 2432 / 16,384 | 39 | 19–21 | 463 | 473, 464 / 465 | 33,334 / 51,376 / 51,024 / 50,496 / 33,878 / 34,608 / 52,256 / 51,552 / 55,898 / 52,608 |
| 2432 / 8,192 | 37 | 20–22 | 461 | 463, 455 / 457 | 32,560 / 50,706 / 50,354 / 49,826 / 33,104 / 33,792 / 51,586 / 50,882 / 55,028 / 51,938 |
| 2304 / 8,192 | 37 | 20–22 | 461 | 463, 456 / 457 | 31,856 / 49,298 / 48,946 / 48,418 / 32,400 / 33,088 / 50,178 / 49,474 / 53,556 / 50,530 |
| 2304 / 4,096 | 36 | 21–23 | 463 | 472, 465 / 466 | 31,482 / 48,724 / 48,372 / 47,844 / 32,026 / 32,714 / 49,604 / 48,900 / 52,950 / 49,956 |
| 2176 / 4,096 | 36 | 21–23 | 467 | 472, 465 / 467 | 30,778 / 47,316 / 46,964 / 46,436 / 31,322 / 32,010 / 48,196 / 47,492 / 51,478 / 48,548 |
| 2048 / 1,024 | 33 | 23–24 | 465 | 474, 466 / 468 | 29,102 / 44,712 / 44,360 / 43,832 / 29,646 / 30,334 / 45,592 / 44,888 / 47,352 / 45,944 |

## 4. What the margin buys

q1 instead of q3 is 0.7–0.9 bit of q and +8 to +14 β at 80 hints for every cell; it turns n = 2304 / K 8,192 into
452.25 (no exception) and n = 2176 / K 4,096 into 442.48. The price is the mint margin 1.24× / 1.30× instead of 3.08×:
the reachable worst case `(K − 1)·B` then sits within 24–30 % of the mint threshold `Δ − E`. Today's design kept 4.14×
on purpose ("q ≈ 2^42 rather than 2^41 buys a 4× accounting margin for 16 β-units", pq-zero-knowledge.md), and v1's
ℓ2 bug once took the margin to ≈ 1.12× (pq-zero-knowledge.md, PQZL v1 note). [inference] q1 is listed for completeness;
it is not recommended.

## 5. Sizes (`sizes.txt`) [measured layout; proofs are codegen estimates]

| candidate | n | K_MAX | log2 q | pk / u B | ct B | acc words | stmt R_TX / R_TX0 / R_BURN / R_REG / disclosure | stmt op 7 M = 4 aud / off | op 1 blob | op 7 M = 4 blob | proofs reg / tx / tx0 / burn / ds / dr / txm2 / txm20 / txm4 / txm40 B | max proof | max input (form) | relayed op 1 / op 7 M = 4 calldata, EIP-7976 floor |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 16k (approved) | 2560 | 16,384 | 50.000 | 20,480 | 20,608 | 644 | 103,552 / 82,944 / 62,336 / 20,576 / 41,376 | 165,760 / 144,768 | 20,912 | 21,776 | 33,734 / 52,624 / 52,272 / 51,744 / 34,278 / 35,142 / 53,504 / 52,800 / 57,202 / 53,856 | 57,202 (58% of MAX_PROOF) | 222,967 (txm4; ≤ MAX_INPUT 261,120) | 78,020 / 83,524, 5,008,280 / 5,360,536 |
| n2048 K1024 | 2048 | 1,024 | 41.691 | 16,384 | 16,512 | 516 | 83,072 / 66,560 / 50,048 / 16,480 / 33,184 | 132,992 / 116,096 | 16,816 | 17,680 | 29,102 / 44,712 / 44,360 / 43,832 / 29,646 / 30,334 / 45,592 / 44,888 / 47,352 / 45,944 | 47,352 (48% of MAX_PROOF) | 180,349 (txm4; ≤ MAX_INPUT 261,120) | 66,012 / 69,578, 4,239,768 / 4,467,992 |
| n2176 K4096 | 2176 | 4,096 | 45.750 | 17,408 | 17,536 | 548 | 88,192 / 70,656 / 53,120 / 17,504 / 35,232 | 141,184 / 123,264 | 17,840 | 18,704 | 30,778 / 47,316 / 46,964 / 46,436 / 31,322 / 32,010 / 48,196 / 47,492 / 51,478 / 48,548 | 51,478 (52% of MAX_PROOF) | 192,667 (txm4; ≤ MAX_INPUT 261,120) | 69,640 / 74,728, 4,471,960 / 4,797,592 |
| n2304 K4096 | 2304 | 4,096 | 45.800 | 18,432 | 18,560 | 580 | 93,312 / 74,752 / 56,192 / 18,528 / 37,280 | 149,376 / 130,432 | 18,864 | 19,728 | 31,482 / 48,724 / 48,372 / 47,844 / 32,026 / 32,714 / 49,604 / 48,900 / 52,950 / 49,956 | 52,950 (54% of MAX_PROOF) | 202,331 (txm4; ≤ MAX_INPUT 261,120) | 72,072 / 77,224, 4,627,608 / 4,957,336 |
| n2304 K8192 | 2304 | 8,192 | 47.800 | 18,432 | 18,560 | 580 | 93,312 / 74,752 / 56,192 / 18,528 / 37,280 | 149,376 / 130,432 | 18,864 | 19,728 | 31,856 / 49,298 / 48,946 / 48,418 / 32,400 / 33,088 / 50,178 / 49,474 / 53,556 / 50,530 | 53,556 (54% of MAX_PROOF) | 202,937 (txm4; ≤ MAX_INPUT 261,120) | 72,646 / 77,830, 4,664,344 / 4,996,120 |
| n2432 K8192 | 2432 | 8,192 | 47.851 | 19,456 | 19,584 | 612 | 98,432 / 78,848 / 59,264 / 19,552 / 39,328 | 157,568 / 137,600 | 19,888 | 20,752 | 32,560 / 50,706 / 50,354 / 49,826 / 33,104 / 33,792 / 51,586 / 50,882 / 55,028 / 51,938 | 55,028 (56% of MAX_PROOF) | 212,601 (txm4; ≤ MAX_INPUT 261,120) | 75,078 / 80,326, 4,819,992 / 5,155,864 |
| n2432 K16384 | 2432 | 16,384 | 49.851 | 19,456 | 19,584 | 612 | 98,432 / 78,848 / 59,264 / 19,552 / 39,328 | 157,568 / 137,600 | 19,888 | 20,752 | 33,334 / 51,376 / 51,024 / 50,496 / 33,878 / 34,608 / 52,256 / 51,552 / 55,898 / 52,608 | 55,898 (57% of MAX_PROOF) | 213,471 (txm4; ≤ MAX_INPUT 261,120) | 75,748 / 81,196, 4,862,872 / 5,211,544 |

Change against the approved 16k set (negative = smaller):
| candidate | pk / ct / acc words | R_TX stmt | op 7 M = 4 stmt | R_TX proof | txm4 proof | max input | op 1 blob |
|---|---|---|---|---|---|---|---|
| n2048 K1024 | -19.9 % | -19.8 % | -19.8 % | -15.0 % | -17.2 % | -19.1 % | -19.6 % |
| n2176 K4096 | -14.9 % | -14.8 % | -14.8 % | -10.1 % | -10.0 % | -13.6 % | -14.7 % |
| n2304 K4096 | -9.9 % | -9.9 % | -9.9 % | -7.4 % | -7.4 % | -9.3 % | -9.8 % |
| n2304 K8192 | -9.9 % | -9.9 % | -9.9 % | -6.3 % | -6.4 % | -9.0 % | -9.8 % |
| n2432 K8192 | -5.0 % | -4.9 % | -4.9 % | -3.6 % | -3.8 % | -4.6 % | -4.9 % |
| n2432 K16384 | -5.0 % | -4.9 % | -4.9 % | -2.4 % | -2.3 % | -4.3 % | -4.9 % |

Every candidate's largest PQZL precompile input (op 7 M = 4 with the auditor) is under Task 7b's proposed `MAX_INPUT`
261,120 (255 KiB) and the 261,909-byte calldata limit; relayed op 1 / op 7 M = 4 calldata shrinks with n.

## 6. Gas [estimate]

| candidate | acc words | old: ROLL_MAX (full relayed tx) | old: prepare half full tx | old: op 1 / op 7 M = 4 execution | precompile op 1 / op 7 M = 4 | Amsterdam: ROLL_MAX (regular gas) | Amsterdam: prepare half regular / state | Amsterdam: op 1 blob state gas | rollovers to fill acc (K_MAX: old / Amsterdam) |
|---|---|---|---|---|---|---|---|---|---|
| n = 2048 | 516 | 256 (12,246,838; 36,323 / entry + 2,948,150) | 5,856,602 | 4,002,873 / 4,468,572 | 5,409,000 / 4,121,000 | 128 (12,375,163; 44,123 / entry + 6,727,419) | 3,224,893 / 25,498,733 | 25,728,480 | 1024: 4 / 8, 4096: 16 / 32, 8192: 32 / 64, 16384: 64 / 128 |
| n = 2176 | 548 | 240 (12,251,399; 38,043 / entry + 3,121,079) | 6,211,130 | 4,234,271 / 4,706,366 | 5,747,062 / 4,378,562 | 112 (12,249,035; 45,843 / entry + 7,114,619) | 3,424,887 / 27,080,050 | 27,295,200 | 1024: 5 / 10, 4096: 18 / 37, 8192: 35 / 74, 16384: 69 / 147 |
| n = 2304 | 580 | 224 (12,200,920; 39,763 / entry + 3,294,008) | 6,565,658 | 4,465,668 / 4,944,159 | 6,085,125 / 4,636,125 | 96 (12,067,867; 47,563 / entry + 7,501,819) | 3,624,880 / 28,661,366 | 28,861,920 | 1024: 5 / 11, 4096: 19 / 43, 8192: 37 / 86, 16384: 74 / 171 |
| n = 2432 | 612 | 208 (12,095,402; 41,483 / entry + 3,466,938) | 6,920,186 | 4,697,066 / 5,181,952 | 6,423,188 / 4,893,688 | 80 (11,831,659; 49,283 / entry + 7,889,019) | 3,824,874 / 30,242,683 | 30,428,640 | 1024: 5 / 13, 4096: 20 / 52, 8192: 40 / 103, 16384: 79 / 205 |
| n = 2560 | 644 | 192 (11,934,843; 43,203 / entry + 3,639,867) | 7,274,714 | 4,928,464 / 5,419,746 | 6,761,250 / 5,151,250 | 80 (12,356,459; 51,003 / entry + 8,276,219) | 4,024,867 / 31,824,000 | 31,995,360 | 1024: 6 / 13, 4096: 22 / 52, 8192: 43 / 103, 16384: 86 / 205 |

- **Old rules** (Foundry 1.3.5, pre-Amsterdam): Task 7's as-built pins at 516 (today) and 644 (16k) acc words,
  linear in between; reproduces `ROLL_MAX` 256 at 516 and 192 at 644.
- **Amsterdam** (Task 7b, commit `9c2f53ef`, Foundry 1.8.5, measured at 644 words only): rollover 51,003 / entry +
  8,276,219, the fixed part = 644 cold `acc` rewrites × 12,100 (EIP-8038) + 483,819; scaled here by the word count
  (fixed) and by the old per-word lane-add slope 53.75 (per entry). Reproduces 7b's `ROLL_MAX` 80 at 644. State gas
  (EIP-8037): the op 1 SSTORE2 blob at 1,530 / byte, a prepare half in proportion to the words.
- **Precompile**: today's PQZL rows (op 1 5,409,000, op 7 M = 4 4,121,000) × n / 2048, as Task 7 did for n = 2560.
- [inference] Under Amsterdam a smaller n pays more than before: the fixed acc rewrite and every state-gas item scale
  with n, so n = 2304 moves `ROLL_MAX` 80 → 96 and cuts each debit's state gas by ≈ 3.1 M; n = 2048 doubles `ROLL_MAX`
  to 128.

## 7. Candidates for the owner and recommendation

| Candidate | β at 80 hints (DDGR20) | sizes vs 16k | `ROLL_MAX` Amsterdam / old | refresh interval `K_MAX` | exception |
|---|---|---|---|---|---|
| A: n = 2560, K 16,384 (approved) | 482.4 (dual 474.4) | — | 80 / 192 | 16,384 | none |
| B: n = 2432, K 16,384 | 450.5 (dual 442.5) | −5 % | 80 / 208 | 16,384 | none by DDGR20 (0.5 β headroom); **yes** by dual_hybrid (−7.5) |
| C: n = 2432, K 8,192 | 476.4 (dual 466.4) | −5 % | 80 / 208 | 8,192 | none |
| D: n = 2304, K 8,192 | 441.9 (dual 434.9) | −10 % | 96 / 224 | 8,192 | **yes** (8.1 below 450; dual 15.1 below; precedent 446.0 of 2026-10-15; Kyber-512 ≈ 406) |
| E: n = 2304, K 4,096 | 468.5 (dual 458.5) | −10 % | 96 / 224 | 4,096 | none |
| F: n = 2176, K 4,096 | 432.6 (dual 424.6) | −15 % | 112 / 240 | 4,096 | **yes** (17.4 below 450; dual 25.4 below; also its 0-hint dual_hybrid is 451) |
| G: n = 2048, K 1,024 | 450.5 (dual 442.5) | −20 % | 128 / 256 | 1,024 | none by DDGR20 (0.5 β headroom); **yes** by dual_hybrid (−7.5) |

"Sizes" = keys, ciphertexts, acc words, statements, op blobs (all ∝ n); proofs fall less (−2 % to −17 %, §3.4).
"dual" = dual_hybrid on the 80-hint instance minus the DDGR20 offset, the lower of classical / quantum [estimate].

**Recommendation [inference; the owner decides].**
1. **If a refresh interval of 4,096 credits is acceptable: E (n = 2304, `K_MAX` 4,096, q ≈ 2^45.80).** It is the only
   −10 % set that clears 450 at 80 hints in both models (468.5 / 458.5) with no exception, its proofs are 7 % smaller,
   its largest input 202 KB, `ROLL_MAX` 96 under Amsterdam (80 at 16k) and a full `acc` takes 43 rollovers instead of
   205; every debit's state gas drops by ≈ 3.1 M and the `acc` rewrite of each rollover by ≈ 0.77 M.
2. **Otherwise keep A (the approved 16k set).** At `K_MAX` 16,384 the only smaller n is B (−5 %), which passes the
   DDGR20 rule by 0.5 β and fails the dual_hybrid view by 7.5: not worth an exception for 5 %. C buys the same 5 % for
   half the refresh interval; E dominates it if the interval may drop.
3. **Not recommended:** D and F (new exceptions below today's 446 precedent, in both models), G (= today's n and
   today's `K_MAX` 1,024: it undoes the `K_MAX` 16,384 change of CTR-PQZ-06, and passes only by DDGR20), and every q1 variant (mint margin 1.12–1.38×, §4).

Switching to E would re-run what Task 7 did for 16k (specs, headers, `estimator-*.txt`, hints table 16–144, gas pins at
580 words) inside the one `proofSystemId` bump already planned (spec §6.4); its prime q = 61,275,424,977,257 ≈ 2^45.80 keeps
every PQZH radix (q − 1 = 2^3·7·17·19·43·431·182,789).

## 8. Files and reruns

| File | What |
|---|---|
| `budget.py` → `budget.txt`, `cells.json` | budget, primes, uSVP shortcut (stdlib) |
| `run_sage.sh` | one Sage script in the pinned image, tools mounted read-only (`--memory 5g --cpus 2`) |
| `screen.sage` → `screen.txt` | uSVP + DDGR20 0 / 32 / 80 for all 41 rows |
| `gen_specs.py` → `specs/n<n>k<K>/` | LaZer specs per promising cell |
| `e_s1_n.sage` → `e-s1-n<n>k<K>.txt` | proof ranks and codegen proof sizes |
| `enc_n.sage` → `enc-n.txt` | full estimates, dual_hybrid at 80 hints |
| `e_s0_n.py`, `run_e_s0_n.sh` → `e-s0-n.txt` | budget, exactness, Fiat–Shamir rounds per cell |
| `sizes.py` → `sizes.txt` | sizes and gas (stdlib) |

```sh
T=<dir with lk (0a9caf8), le (53da598), lz (3330e48)>; P=pqz-core/pqzl/params/n-study
python3 -I $P/budget.py > $P/budget.txt
scripts/capped $P/run_sage.sh $T screen.sage > $P/screen.txt
python3 -I $P/gen_specs.py <n> <K_MAX> <q>            # per cell, q from cells.json (variant q3)
scripts/capped $P/run_sage.sh $T e_s1_n.sage /p/specs/n<n>k<K>/{reg,tx,tx0,burn,ds,dr,txm2,txm20,txm4,txm40}_params.sage > $P/e-s1-n<n>k<K>.txt
ROWS=0,10,18,20,28,30 scripts/capped $P/run_sage.sh $T enc_n.sage > $P/enc-n.txt
N=<n> K_MAX=<K> Q=<q> scripts/capped $P/run_e_s0_n.sh >> $P/e-s0-n.txt
python3 -I $P/sizes.py > $P/sizes.txt
```
