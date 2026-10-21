# 16k parameter candidate: results for the owner checkpoint (plan 5h Task 7)

**Status:** measured candidate, 2026-10-21; fix round 1 (review I1, I2, m3, m4) the same day. Nothing in production changed: no header, Rust / C / Solidity constant, id or
vector. Plan Task 8 switches the code after this checkpoint. Plan: `docs/superpowers/plans/2026-10-20-pqz-state-redesign.md`
(D16, D23, D25); spec §6.

**Amsterdam (Task 7b, §8):** the SCaaS testnet and the owner's rules are now Amsterdam; §8 re-measures the gas with
Foundry 1.8.5 and supersedes §6's Osaka gas figures: `ROLL_MAX` = **80** (not 192), `MAX_INPUT` proposal 261,120.

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
| DDGR20 worst case at 144 hints (one group: 8 legs + auditor) | **β 462.68** (primal, DDGR20) | ≥ 450 |
| dual_hybrid at 144 hints (n − h model; and minus the DDGR20 worst-case offset 7.32) | **461 / 463** (classical / quantum); **453.68 / 455.68** | ≥ 450 → both models: **M = 8 uses G = 1** |
| Smallest proof-instance β (all 14 specs, both models) | **455** (MSIS of R_TX / R_TX0 / R_BURN / R_TXM M = 2, M = 4 off); hiding MLWE uSVP ≥ 471, dual_hybrid **462 / 463** | ≥ 450 |
| Largest PQZL codegen proof | **76,002 B** (R_TXM M = 8, G = 2, auditor); G = 1: **60,882 B** | `MAX_PROOF` 98,304 |
| Largest PQZL precompile input | 345,191 B (M = 8, G = 2, auditor); G = 1: 309,591 B | `MAX_INPUT` 512 KiB (also under today's 393,216) |
| `ROLL_MAX`, full relayed transaction with a fee (binding convention, fix round 1) | **192** (11,934,843 gas); 208: 12,626,103 — over | 0.75 · 2^24 = 12,582,912 |
| `ROLL_MAX`, execution gas of the call only, fee 0 (first round's convention) | 208 (12,564,860); 224: 13,256,108 | 12,582,912 |
| `mtxPrepareAcc` half, full relayed transaction with a fee | 7,274,714 (execution only: 7,176,058 direct, 7,213,421 relayed) | 12,582,912 |
| op 7 M = 8 relayed transaction, G = 2 | 13,210,485 measured + precompile ≈ 7.72 M [estimate] ≈ 20.96 M — **does not fit** | 2^24 = 16,777,216 |
| op 7 M = 8 relayed transaction, G = 1 | 7,938,513 measured + ≈ 7.72 M [estimate] ≈ 15.69 M — fits while the precompile row ≤ **8,809,678** (1.43× today's 6,177,000; direct call: ≤ 9,059,115, 1.47×) | 2^24 |
| n = 2304 at 80 hints | β 415.29 (0 hints: 439.58; key uSVP 440) — **does not clear 450**: no owner checkpoint | ≥ 450 |
| PQZH Ligero proof bound, debit forms | **≈ 302.7 KB [estimate] — over `MAX_PROOF_PQZH` 262,144** (owner) | 262,144 |
| e_s0 checks at 16k (budget, exactness, Fiat–Shamir rounds) | all met | — |

**Decisions the numbers force (O9 rule):**
1. **op 7 M = 8 uses one randomness group (G = 1)**: 144 worst-case hints give β 462.68 ≥ 450 under DDGR20 (auditor
   off, 128 hints: 467.60), and dual_hybrid 461 / 463 on the n − h model (453.68 / 455.68 after subtracting the
   worst-case offset), so both models clear 450. Groups of up to 8 legs share one `(r, e1)`. This is a new relation shape (`txm8g1` / `txm80g1` here),
   and on chain it is also the only M = 8 shape that fits 2^24 (§6). Task 8: `G = ⌈M / 8⌉` (or G = 1 for M ≤ 8) in the
   relation, `pqz-stmt`, both cores and the Solidity layout.
2. **`ROLL_MAX = 192`** (recommendation, fix round 1): the largest multiple of 16 whose **full relayed transaction**
   — 21,000 intrinsic, the envelope's calldata, a cold implementation, a non-zero absolute outer fee to a fresh relayer
   — stays ≤ 0.75 · 2^24: 192 → 11,934,843 (648 k margin), 208 → 12,626,103 (over by 43 k). The first round's 208
   held only for the execution gas of a fee-0 call (18 k margin). With 192 the direct-call pin `test_gas_rollMax`'s
   "`ROLL_MAX` + 16 over it" assertion (execution-only convention) no longer holds (208 direct = 12,527,572): Task 8
   re-pins it on the full-transaction convention.
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

**dual_hybrid on the hinted instance** (fix round 1, `dual_hints16k.sage`, appended to `hints-16k-n2560.txt` as
section 6): h hints on r as h removed secret dimensions (LWE n = 2560 − h, m = 2576), as the "estimator n − h" column;
"− offset" subtracts (n − h primal − DDGR20 mixed), the worst-case penalty of DDGR20 over that model [estimate]:

| hints | primal n − h | dual_hybrid classical / quantum | DDGR20 mixed | offset | dual_hybrid − offset |
|---|---|---|---|---|---|
| 0 | 508 | 499 / 500 | 507.31 | 0.69 | 498.31 / 499.31 |
| 16 | 504 | 495 / 495 | 502.32 | 1.68 | 493.32 / 493.32 |
| 32 | 499 | 490 / 493 | 497.34 | 1.66 | 488.34 / 491.34 |
| 80 | 486 | 478 / 480 | 482.43 | 3.57 | 474.43 / 476.43 |
| 128 | 474 | 465 / 467 | 467.60 | 6.40 | 458.60 / 460.60 |
| **144** | 470 | **461 / 463** | 462.68 | 7.32 | **453.68 / 455.68** |

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
(`ROLL_MAX` = 208, op 7 proof 76,002 B), `gas-16k-r192.txt` (the recommended 192 build), `gas-16k-r208-n192.txt`
(192 entries full transaction in the 208 build), `gas-16k-r224.txt` (the 224 build), `gas-16k-r208-g1.txt` (`G1=1`: one group
for M ≤ 8, proof 60,882 B), `gas-today-n2048.txt` (the same tests at today's sizes).

| Call | today (n = 2048) | 16k (n = 2560) |
|---|---|---|
| `mtxRollOver` 1 / 16 / 128 | 2,854,442 / 3,430,787 / 7,498,963 | 3,553,051 / 4,232,596 / 9,071,332 |
| `mtxRollOver` `ROLL_MAX` direct / relayed (execution, fee 0) | 256: 12,148,307 / 12,185,595 | 208: 12,527,572 / 12,564,860; 192: 11,836,324 / 11,873,612 |
| `ROLL_MAX` + 16 relayed (own build, execution, fee 0) | — | 224: 13,256,108 (> 12,582,912) |
| `mtxRollOver` full relayed transaction, fee 7 (fix round 1) | 256: 12,246,838 | **192: 11,934,843**; 208: 12,626,103 (over) |
| `mtxPrepareAcc` half 0, full relayed transaction, fee 7 | 5,856,602 | 7,274,714 |
| fit: per entry / fixed | 36,323 / 2,849,619 | 43,203 / 3,541,348 |
| `ROLL_MAX` after a TRIVIAL-only rollover | 12,088,219 | 12,467,484 (208); 11,776,236 (192) |
| `mtxPrepareAcc` half 0 / 1, direct / relayed | 5,757,946 / 5,795,309 | **7,176,058 / 7,213,421** |
| op 1 BUNDLE, auditor, fresh ref | 4,002,873 | 4,928,464 |
| op 1, materialised `acc`, hint / no hint | 4,133,936 / 5,229,390 | 5,072,798 / 6,433,509 |
| op 7 M = 4, auditor | 4,468,572 | 5,419,746 |
| op 7 M = 8, auditor, G = 2 / G = 1 (2-byte proof) | 8,586,995 / — | 10,484,989 / 6,058,863 |
| burn / refresh | 3,857,681 / 3,832,302 | 4,769,650 / 4,744,270 |
| shield append / merge | 73,940 / 51,774 | 73,940 / 51,774 |

**Full-transaction convention (fix round 1).** `_fullTx` in `PqzStateGas.t.sol` relays the call through `mtxExecute`
with a FIXED (absolute) outer fee of 7 paid from the signer's public balance to a fresh relayer (a zero → non-zero
balance write), computes the digest under a snapshot that is reverted (so the clone's implementation and libraries
are cold in the measured call; `tok` itself is cold too, +2,600 against chain, conservative), and reports
`21,000 + max(EIP-2028 calldata + execution, EIP-7623 floor)` of the real `mtxExecute` calldata. The UA envelope
(`uaExecute`, ML-DSA auth) was not measured: its ML-DSA precompile is mocked here.

**op 7 M = 8 against the 2^24 transaction gas cap** (first round: direct call; fix round 1: the relayed full transaction):

| | today (G = 2) | 16k G = 2 | **16k G = 1** |
|---|---|---|---|
| proof (codegen) | 64,578 | 76,002 | 60,882 |
| calldata bytes | — | 123,428 | 87,812 |
| execution, precompile mocked (measured) | 9,017,286 | 11,081,772 | 6,414,824 |
| calldata EIP-2028 (measured; all-non-zero bound) | 1,453,236 | 1,729,664 (1,974,848) | 1,253,252 (1,404,992) |
| 21,000 + calldata + execution (measured) | 10,491,522 | 12,832,436 | 7,689,076 |
| precompile schedule gas | 6,177,000 (today's row) | ≈ 7.72 M [estimate] | ≈ 7.72 M [estimate] |
| **total, direct** | 16,668,522 (fits by 0.11 M) | **≈ 20.6 M: over 2^24** | **≈ 15.4 M: fits (≈ 1.3 M margin)** [estimate] |
| relayed full tx, fee 7: `mtxExecute` calldata bytes | 104,356 | 123,972 | 88,356 |
| relayed: execution / calldata gas (measured) | 9,316,891 / 1,456,648 | 11,456,409 / 1,733,076 | 6,660,849 / 1,256,664 |
| relayed: 21,000 + calldata + execution (measured) | 10,794,539 | 13,210,485 | **7,938,513** |
| **total, relayed** (+ precompile, + 3 gas per input word ≈ 29–33 k) | ≈ 17.0 M: over | ≈ 20.96 M: over | **≈ 15.69 M: fits (≈ 1.09 M margin)** [estimate] |
| **precompile tolerance**: the largest op 7 M = 8 row that still fits 2^24 | — | none (≤ 3.53 M) | **relayed 8,809,678 (1.43× today's row); direct 9,059,115 (1.47×)** |

The precompile estimate is today's PQZL op 7 M = 8 row scaled by the statement ratio 1.25 (n 2048 → 2560), applied
to G = 1 too (its statement is 8 % smaller, so this is conservative); input words add 3 · ⌈309,591 / 32⌉ = 29,025 for
G = 1. G = 2 is over the cap even with today's unscaled 6.18 M (19.0 M direct). **Tolerance:** G = 1 fits relayed while
Task 9's calibrated row is ≤ 8,809,678 = 2^24 − 7,938,513 − 29,025; the 7.72 M estimate leaves 14 % headroom (direct: 17 %), so a
calibration at the top of the reviewer's +18 % spread (≈ 9.11 M) would fit **neither** path (relayed ≤ 8,809,678,
direct ≤ 9,059,115): M = 8 on chain then needs either a calibrated row inside the tolerance or a smaller op 7 cost. Today's M = 8 relayed is already over (≈ 17.0 M), so relayed op 7
M = 8 does not run on today's parameters either.

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
| `gas16k.sh` → `gas-16k-*.txt`, `gas-today-n2048.txt` | the as-built gas pins at the 16k sizes (`r192`, `r208`, `r208-n192`, `r208-g1`, `r224`) |
| `dual_hints16k.sage` (`SCRIPT=… run_enc16k.sh`) → section 6 of `hints-16k-n2560.txt` | dual_hybrid on the hinted instance |

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
PQZ_ROLL_N=192 scripts/capped $P/gas16k.sh <work dir> <lib> 208 --match-test test_gas_rollMax_relayedFullTx -vv > $P/gas-16k-r208-n192.txt
PQZ_PROOF_LEN=76002 scripts/capped $P/gas16k.sh <work dir> <lib> 192 > $P/gas-16k-r192.txt
SCRIPT=dual_hints16k.sage scripts/capped $P/run_enc16k.sh $T/le >> $P/hints-16k-n2560.txt
PQZ_PROOF_LEN=60882 G1=1 scripts/capped $P/gas16k.sh <work dir> <lib> 208 --match-test test_gas_op7 -vv > $P/gas-16k-r208-g1.txt
```

## 8. Amsterdam re-measure, SCaaS testnet (plan 5h Task 7b, 2026-10-21)

**Why.** The testnet (7622) runs Nethermind 2.2.0 with Amsterdam from block 1; the owner keeps Ethereum's rules (EIP-7976
calldata floor, EIP-8037 state gas, EIP-8038 storage repricing, EIP-2780 intrinsic). §6 was measured with Foundry 1.3.5
(Osaka rules). Rulings applied, not revisited: op 7 on chain M ≤ 4, PQZH backup only (no PQZH token), no multi-tx
staging; the `ROLL_MAX` rule is "regular (execution) gas ≤ 0.75 · 2^24 = 12,582,912 as a full relayed transaction".

**How.** Foundry **1.8.5** (`51a52c59`; the machine-wide `~/.foundry/bin` after the owner's upgrade; an identical
copy from the checksum-verified release tarball sits in `~/usr/foundry-1.8.5/`). `gas16k.sh` gained `EVM=amsterdam`:
the work tree's default profile only gets `evm_version = "amsterdam"` and `experimental = true` (solc 0.8.37 accepts
"amsterdam" only as experimental; the bytecode is identical to the Osaka build except the metadata hash, checked for
the token, its four libraries, `UARegistry`, `OpenFactory`, `UAPqzVerifier`, `MetaTxLib`). No code-size setting is
needed (EIP-7954: 65,536 B native). Foundry 1.8 runs each top-level call of a test as its own transaction
(`isolate = true`), so `PqzStateGas.t.sol` now reads `vm.lastCallGas()`: **regular** gas before refunds (intrinsic
12,000 + 3,000, calldata 4 / 16 or the EIP-7976 floor 15,000 + 64 per byte, execution) and **state** gas apart; `setUp`
runs unmetered (it is one transaction and would hit the 2^24 regular cap). The full relayed transaction is the §6
convention (`mtxExecute` from a fresh relayer, ABSOLUTE fee 7 to it, cold implementation; `tx.to` warm as on chain).
The precompile part is today's PQZL v3 row × 1.25 **[estimate]** (op 1 auditor 5,409,000 → 6,761,250; op 7 M = 1 / 2 / 4
auditor 3,625,000 / 3,710,000 / 4,121,000 → 4,531,250 / 4,637,500 / 5,151,250) plus ML-DSA-65 68,006 (unchanged),
burnt inside the transaction by stand-in contracts at `PQZ` / `ML65` (`GasBurner`, less the 2,900 cold-account
difference; ±40 gas), so the floor is compared with the whole transaction. No timing or calibration run.

### 8.1 Headline

| Item | Amsterdam (16k) | Limit | §6 (Osaka) |
|---|---|---|---|
| **`ROLL_MAX` proposal** | **80**: relayed full tx regular **12,356,459**, state 195,840, total 12,552,299 (margin 226,453); 96: 13,172,507 — over | 12,582,912 regular | 192 (11,934,843) |
| rollover fit, relayed full tx | **51,003 per entry + 8,276,219** (direct call: 51,003 + 8,211,680) | — | 43,203 + 3,541,348 |
| `mtxPrepareAcc` half 0 / 1, relayed full tx | regular **4,024,867**, state 31,824,000, total 35,848,867 (each) | 12,582,912 regular | 7,274,714 |
| op 1 relayed, auditor, 52,624 B proof (fresh ref / materialised acc, no hint) | regular **8,926,563 / 10,534,720**, state 32,768,010 / 32,865,930 [estimate: precompile] | 2^24 regular | — |
| op 7 M = 1 / 2 / 4 relayed, auditor | regular **6,717,641 / 6,921,774 / 7,679,749**, state 32.9 / 33.5 / 34.8 M [estimate: precompile] | 2^24 regular | — |
| one transaction's calldata (EIP-7976 + EIP-8037) | **261,909 B** (15,000 + 64 · n ≤ 2^24) | — | none |
| largest PQZL 16k form, M ≤ 4: precompile input / relayed calldata | 222,967 B (op 7 M = 4, auditor) / 83,524 B | 261,909 | — |
| **`MAX_INPUT` proposal** | **261,120 (255 KiB)**: ≤ the 261,909 B a direct call to `PQZ` can carry | — | 393,216 |
| Foundry 1.8.5 vs Nethermind 2.2.0 on the same transactions | **equal to the gas** (`cast run` = receipt, 10 of 10 replayable transactions) | — | — |

### 8.2 `ROLL_MAX` (`gas-amsterdam-scan-r192.txt`, `gas-amsterdam-r80.txt`, `gas-amsterdam-r96.txt`)

Relayed full transaction (`test_gas_rollMax_relayedFullTx`, `PQZ_ROLL_N` entries in the 192 build; 80 and 96 in their
own builds give the same numbers):

| entries | 64 | **80** | 96 | 112 | 128 | 144 | 160 | 176 | 192 |
|---|---|---|---|---|---|---|---|---|---|
| regular | 11,540,411 | **12,356,459** | 13,172,507 | 13,988,555 | 14,804,603 | 15,620,651 | 16,436,699 | 17,252,747 | 18,068,783 |

State gas 195,840 at every size (two new slots of the envelope: the fresh relayer's fee balance, and one more the fee-0 relay
also writes, 97,920; the rollover itself writes no new slot). Refunds (not subtracted; the cap is on gas before refunds): 929,280 at 80 (80 deleted
pending slots), 2,230,272 at 192. Exactly linear: **51,003 per entry, 8,276,219 fixed**. The fixed part is the 644
`acc` words rewritten cold: 644 × (2,100 + 10,000 EIP-8038 storage write) = 7.79 M of it (§6: 644 × 5,000). In the 80
build every pin passes: direct `ROLL_MAX` 12,291,920; relayed fee 0 12,327,969; ROLL_MAX after a TRIVIAL-only
rollover 12,144,632; 1 / 16 / 40 entries 8,232,683 / 9,027,728 / 10,251,800. In the 96 build the four `ROLL_MAX` pins fail
(13,107,968 direct, 13,172,507 relayed full tx, 12,960,680 after TRIVIAL). The direct-call pin's fit point moved from
128 to `ROLL_MAX / 2` (128 at today's 256; 128 > 80 cannot be rolled) and its "`ROLL_MAX` + 16 over the cap" assertion
became a log line (direct-call convention; §6 already noted Task 8 re-pins on the full-transaction convention).
The Nethermind note's inference (≈ 80–96, `pqz-core/nethermind/runs/2026-10-21-glamsterdam-gas-impact.md`) holds.

### 8.3 The prepare halves, op 1 and op 7 (`gas-amsterdam-r80.txt`, `gas-amsterdam-r80-mocked.txt`)

| relayed full transaction (fee 7) | proof B | calldata B | EIP-7976 floor | regular, precompile mocked | **regular with the precompile [estimate]** | state | total |
|---|---|---|---|---|---|---|---|
| `mtxPrepareAcc` half 0 / 1 | — | 612 | 54,168 | 4,024,867 | — | 31,824,000 | 35,848,867 |
| `mtxRollOver` 80 | — | 612 | 54,168 | 12,356,459 | — | 195,840 | 12,552,299 |
| op 1, auditor, fresh ref | 52,624 | 78,020 | 5,008,280 | 5,008,280 (= floor) | **8,926,563** | 32,768,010 | 41,694,573 |
| op 1, auditor, materialised acc, no hint | 52,624 | 78,020 | 5,008,280 | 5,008,280 (= floor) | **10,534,720** | 32,865,930 | 43,400,650 |
| op 7 M = 1, auditor | 52,624 | 78,084 | 5,012,376 | 5,012,376 (= floor) | **6,717,641** | 32,865,930 | 39,583,571 |
| op 7 M = 2, auditor | 53,504 | 79,236 | 5,086,104 | 5,086,104 (= floor) | **6,921,774** | 33,502,410 | 40,424,184 |
| op 7 M = 4, auditor | 57,202 | 83,524 | 5,360,536 | 5,360,536 (= floor) | **7,679,749** | 34,775,370 | 42,455,119 |

- **Every form fits**: regular ≤ 10.53 M < 2^24 (op 1 worst case: the PQZ row may grow to 13,003,746 = 2.40× today's
  5,409,000 before op 1 leaves 2^24; op 7 M = 4: 14,248,717, 3.46×), and every floor ≤ 5.36 M ≤ 2^24. With the precompile
  mocked the floor binds (EVM part ≈ 2.1–3.8 M); with it, the standard path does. Proof sizes: the 16k codegen sizes
  (M = 1 uses `R_TX`'s parameters). op 7 M = 8 (ruled out on chain) relayed, G = 2, mocked: regular 7,218,072 (floor),
  state 68,655,690.
- **State gas dominates the total**: every debit stores its op blob by SSTORE2 (≈ 20.9 KB of code: 1,530 per byte +
  183,600 for the account ≈ 32.0 M) and new slots (97,920 each); a prepare half creates 322 slots (31.5 M). A transaction's
  total (`tx.gas`) may exceed 2^24 (≤ 2^32 − 1), but it must fit the block gas limit: on the testnet today (≈ 40.5 M at
  block 903, rising toward the 200 M target) a debit of ≈ 41–43 M is not includable yet, and a block holds
  ⌊gasLimit / ≈ 33 M⌋ debits in the state dimension. The relayer must set `tx.gas` ≥ regular + state (else the state gas
  spills into the 2^24 regular budget).
- burn / refresh (direct, 2-byte proof) regular 1,590,168, state 32.0 / 31.9 M; shield append / first entry / merge
  regular 106,760 / 103,939 / 94,594, state 97,920 / 195,840 / 0.

### 8.4 Inputs and calldata per form (`inputs16k.py` → `inputs-amsterdam-16k.txt`)

One transaction carries at most **261,909 calldata bytes** (to ≠ sender, no value, no access list): the EIP-7976 floor
15,000 + 64 · n must be ≤ 2^24, else Nethermind refuses it at any gas limit (EIP-8037). Through the token the precompile
input (5 + statement + proof) is built in **memory** from state (keys, `acc`, entries) plus the calldata's payload and
proof; only a direct call to `PQZ` (eth_call probes, the self-test) carries the input itself as calldata.

| form (16k) | statement | proof | input | direct call ≤ 261,909 | entry point | tx calldata | fits | max proof in one tx |
|---|---|---|---|---|---|---|---|---|
| R_TX op 1, auditor / off | 103,552 / 82,944 | 52,624 / 52,272 | 156,181 / 135,221 | yes | relayed `mtxExecute` | 78,020 / 77,540 | yes | 236,512 / 236,640 |
| R_BURN op 2 | 62,336 | 51,744 | 114,085 | yes | relayed `mtxExecute` | 76,868 | yes | 236,768 |
| R_REG op 3 | 20,576 | 33,734 | 54,315 | yes | `UARegistry.register` | 59,812 | yes | 235,840 |
| R_DS / R_DR op 4 / 5 | 41,376 | 34,278 / 35,142 | 75,659 / 76,523 | yes | `verifyTransferAmount` (eth_call) | 34,500 / 35,364 | yes | 261,696 |
| R_TXM op 7 M = 1, auditor / off | 103,552 / 82,944 | 52,624 / 52,272 | 156,181 / 135,221 | yes | relayed | 78,084 / 77,604 | yes | 236,448 / 236,576 |
| R_TXM op 7 M = 2, auditor / off | 124,288 / 103,552 | 53,504 / 52,800 | 177,797 / 156,357 | yes | relayed | 79,236 / 78,276 | yes | 236,160 / 236,416 |
| R_TXM op 7 M = 4, auditor / off | 165,760 / 144,768 | 57,202 / 53,856 | **222,967** / 198,629 | yes | relayed | 83,524 / 79,652 | yes | 235,584 / 236,096 |
| (ruled out) op 7 M = 8, G = 1, auditor | 248,704 | 60,882 | 309,591 | no | relayed | 88,356 | yes | 234,432 |
| PQZH R_REG [estimate] | 20,576 | 233,289 | 253,870 | yes | `register` | 259,364 | yes (2,545 B margin) | 235,840 |
| PQZH R_DS / R_DR [estimate] | 41,376 | 233,289 | 274,670 | **no** | eth_call | 233,508 | yes | 261,696 |
| PQZH R_TX op 1 / op 7 M = 4, auditor [estimate] | 103,552 / 165,760 | 302,743 / 303,590 | 406,300 / 469,355 | no | relayed | 328,132 / 329,924 | **no** | 236,512 / 235,584 |

Statements: today's v3 `stmtLen` with each 16,384-byte unit at 20,480 (reproduces Task 7's 103,552, 165,760, 269,184);
calldata: the ABI layout of each entry point (reproduces the measured 78,020 / 78,084 / 79,236 / 83,524 and Task 7's
88,356). Every PQZL form fits one transaction with ≥ 178 KB to spare; PQZH debit forms cannot be carried by any
transaction (as "PQZH backup only" assumes); PQZH R_REG fits narrowly. The Nethermind note's statement that op 7 M = 8
"cannot be sent at all" holds for a **direct** call to `PQZ` only; through the token its calldata is 88 KB (moot: M ≤ 4).

**`MAX_INPUT` proposal: 261,120 B (255 KiB)**, the largest whole KiB a single transaction can carry to `PQZ`
(≤ 261,909). It covers every PQZL 16k form up to op 7 M = 4 (largest 222,967; 38 KB margin) and PQZH R_REG (253,870). Not
covered: PQZH R_DS / R_DR (274,670; only reachable through the token's in-memory input) and every PQZH debit form.

### 8.5 Cross-check on the SCaaS testnet (`gas-amsterdam-xcheck7622.txt`, `xcheck/`)

`xcheck/PqzGasHarness.sol` puts the as-built `PqzStateLib` / `PqzTransferLib` (16k work tree, `ROLL_MAX` = 80) behind a
contract that is its own registry and whose `pqz` answers 1 (`PqzOk`): the rollover, prepare and op 1 code paths of the
token without the registry stack, the factory or the precompiles (the token itself needs the `PQZ` / ML-DSA precompiles
to accept mock proofs, which a live chain cannot fake). `xcheck/xcheck7622.py` (stdlib; signs with the RUNBOOK's
`eth.py`) built the gas test's state with real transactions from a fresh key funded once from the dev key `0x…04`
(3 key pointers, 96 op blobs of q − 1 coefficients, the pending slots), then sent the measured transactions; nonce
latest = pending at the end (no pending transaction). `xcheck/replay.py` re-executes each with Foundry
(`cast run --evm-version amsterdam`) on the node's state.

| transaction (block) | calldata B | Nethermind eth_estimateGas | Nethermind receipt | Foundry `cast run` |
|---|---|---|---|---|
| 1 ETH to the fresh account (922) | 0 | 207,391 | 204,600 | 204,600 |
| deploy `PqzStateLib` (924) | 6,472 | 10,217,263 | 10,135,654 | 10,135,654 |
| deploy `PqzTransferLib` (926) | 13,632 | 21,377,789 | 21,208,302 | (state pruned) |
| key pointer, 20,481 B code (932) | 20,580 | 32,148,944 | 31,644,317 | (state pruned) |
| op blob, 20,785 B code (944; 1130 / 1132 / 1134) | 20,868 | 32,584,919 | 32,327,187 | 32,327,187 (1130–1134) |
| prepareAcc half 0 (1140) | 68 | 35,862,808 | 35,579,266 | 35,579,266 |
| prepareAcc half 1 (1142) | 68 | 35,764,123 | 35,481,358 | 35,481,358 |
| rollOver 16, first materialisation (1144) | 68 | 8,951,806 | 8,809,635 | 8,809,635 |
| **rollOver 80, distinct cold blobs (1146)** | 68 | 12,485,685 | **11,359,017** | **11,359,017** |
| op 1, auditor, fee, 52,624 B proof (1148) | 77,444 | 34,748,704 | 34,473,934 | 34,473,934 |

The harness rollover of 80 is the token's path: 11,359,017 after its refund of 929,280 (the token's relayed full-tx log
for 80) is 12,288,297 before it, against the token's direct `ROLL_MAX` pin 12,291,920 (the entry point adds ≈ 3.6 k).
The prepare halves on chain (35,579,266 / 35,481,358 total) sit next to the token's direct pins (3,960,178 + 31,628,160 =
35,588,338). The relayed envelope (`mtxExecute`, fee) and the precompiles were not on chain (no token there).

**Foundry vs Nethermind.**
1. **Same gas on the same transactions**: every replayable transaction gives the receipt's gas exactly (10 of 10; the
   three older ones could not be replayed because the node keeps only recent state, error −32002). eth_estimateGas is
   0.8–9.9 % above the receipt (largest for the rollover: the receipt is after the refund of the 80 deleted slots).
2. **The calldata floor with state gas — forge test convention ≠ chain**: Nethermind (and `cast run`) charge
   max(regular + state, floor); the forge test's `vm.lastCallGas()` reports regular = max(regular, floor) and the state
   gas on top (op blob: Nethermind 32,327,187 = 342,537 regular + 31,984,650 state; a forge-test probe of the same
   call: 1,350,552 (the floor) + 31,984,650; key pointer 31,644,317 = 124,787 + 31,519,530 vs 1,332,120 + 31,519,530). So the forge figures are conservative where the floor binds (the mocked op rows of 8.3); they do not
   change any conclusion here (the rollover and prepare floors are 54,168; with the precompile the op rows are above
   their floors). For the 2^24 rule the floor is checked on its own (≤ 2^24) and the execution budget is 2^24 − intrinsic.
3. **Receipts are after refunds, the cap is before**: the rollover's receipt 11,359,017 is 12,288,297 before its
   929,280 refund (≤ 1/5); the 2^24 cap and the `ROLL_MAX` rule apply before refunds, as the forge figures are.
4. **anvil 1.8.5 does not price Amsterdam's state**: the same driver against `anvil --hardfork amsterdam` gives the old
   prices (op blob 4,521,637, 96 new slots 2,260,120, rollover 80 6,645,197; `gas-amsterdam-anvil-dryrun.txt`) while
   `forge test` / `cast run` with `amsterdam` apply EIP-8037 / 8038. Do not size gas on anvil.
5. A value transfer to a NEW account costs 204,600 (21,000 + 183,600 state gas): a 21,000 gas limit fails (attempt 1).

### 8.6 Files and reruns

| File | What |
|---|---|
| `gas16k.sh` (`EVM=amsterdam`) → `gas-amsterdam-r80.txt`, `-r96.txt`, `-r80-mocked.txt`, `-scan-r192.txt` | the pins at the 16k sizes under Amsterdam |
| `inputs16k.py` → `inputs-amsterdam-16k.txt` | inputs and calldata per form, the one-transaction limit |
| `xcheck/PqzGasHarness.sol` | the harness (measurement only; `PqzOk`, its own registry) |
| `xcheck/xcheck7622.py`, `xcheck/replay.py` → `gas-amsterdam-xcheck7622.txt` | the testnet run and Foundry's replay |
| `gas-amsterdam-anvil-dryrun.txt` | the driver's dry run on anvil (old prices, item 4) |
| `gas-today-n2048-forge185.txt` | the edited `PqzStateGas.t.sol` at today's sizes (repo, Osaka, forge 1.8.5): 34 / 34 pass |

```sh
P=pqz-core/pqzl/params/p16k; W=<work dir>; L=smartcontracts/evm/lib   # forge 1.8.5
EVM=amsterdam scripts/capped $P/gas16k.sh $W $L 80 > $P/gas-amsterdam-r80.txt
PQZ_PRECOMPILE=0 EVM=amsterdam scripts/capped $P/gas16k.sh $W $L 80 --match-test 'relayedFullTx_(M|fresh|mat)' -vv > $P/gas-amsterdam-r80-mocked.txt
EVM=amsterdam scripts/capped $P/gas16k.sh $W $L 96 --match-test test_gas_rollMax -vv > $P/gas-amsterdam-r96.txt
for n in 64 80 96 112 128 144 160 176 192; do PQZ_ROLL_N=$n EVM=amsterdam scripts/capped $P/gas16k.sh $W $L 192 --match-test test_gas_rollMax_relayedFullTx -vv; done
python3 -I $P/inputs16k.py > $P/inputs-amsterdam-16k.txt
# testnet: the 80 work tree plus the harness
mkdir -p $W/evm/test/xcheck && cp $P/xcheck/PqzGasHarness.sol $W/evm/test/xcheck/ && scripts/capped sh -c "cd $W/evm && forge build"
python3 -I $P/xcheck/xcheck7622.py --eth <nethermind-2.2>/pqz-core/nethermind/chain --out $W/evm/out --rpc http://127.0.0.1:8545 --dev-key 0x…04 --roll 80 > log
python3 -I $P/xcheck/replay.py log http://127.0.0.1:8545 >> log
```
