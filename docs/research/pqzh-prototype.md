> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH prototype: `R_REG` and `R_TX` as a Plonky3 STARK (P6-PQZH, E-S1H)

Written 2026-10-13 for the owner's P6-PQZH prototype (TODO P6-PQZH; design study `pqzh-design.md`, steps 0–4 of its
§7). Question: what do `R_REG` and `R_TX`, proved by a hash-based STARK (Plonky3 0.8.0, Goldilocks, FRI, Keccak,
LogUp, design D1), cost in proof bytes, prove and verify time, memory, wasm32 and zero-knowledge mode, and which FRI
setting reaches 128 bits — provable and conjectured — within the 160 KB PQZH limit? Code: crate `pqz-core/pqzh/`
(branch `pqzh-proto`, not merged yet); raw runs `pqz-core/pqzh/runs/`. **No decision is recorded here.**

**Follow-up (2026-10-14):** the next step — `R_TX` on the §7.7 layout, the EVM-friendly configuration, ZK +
Goldilocks⁵ at 128 bits proven and conjectured, Merkle caps, WHIR — is in `pqzh-zk-ext5.md` (branch `pqzh-next`);
the numbers below are the prototype's and stay as measured.

**[measured]** marks a number from a run in this note (machine in §2). **[model]** marks a number computed by
Plonky3's own soundness calculator (`p3-security` 0.8.0) from the measured AIR shapes. **[estimate]** marks a rough
figure; **[inference]** a conclusion drawn here.

## 1. Result

**Both relations prove and verify; at the default parameters (Goldilocks², blowup 16, 28 queries, 16 grinding bits,
FRI arity 8) `R_TX` is 141,079 B and `R_REG` 110,388 B, within 160 KB; `R_TX` proves in 2.57 s native / 4.43 s wasm32
and verifies in 8.2 ms p50 / 11.0 ms p99 native, 15.6 ms p99 wasm32, every mutated input rejected [measured].** The
open problems are not verifier speed:

1. **Soundness.** The default is 128 bits only by the old ethSTARK formula (queries × log blowup + grinding bits).
   Plonky3's calculator gives it **100.6 bits conjectured, 71.9 bits proven** [model]. Over Goldilocks² no query count
   reaches 128 bits in either regime: the opening-batching round (340 batched columns over a 2^19-point domain, one
   challenge from a 2^128 field) caps both at ≈ 100–105 bits (§7). The quintic extension Goldilocks⁵, which Plonky3
   supports and the prototype now builds (`Params::ext5`), lifts the cap to the 128-bit hash bound.
2. **No setting reaches 128 bits proven within 160 KB.** The smallest 128-bit proven `R_TX` is **288,945 B**
   (Goldilocks⁵, blowup 32, arity 4, 42 queries, 24 grinding bits); `R_REG` 214,496 B [measured sizes, model bits].
   **128 bits conjectured fits only just**: `R_TX` 160,813 B (Goldilocks⁵, blowup 32, arity 8, 21 queries, 24
   grinding bits; 3 KB under the limit), but that setting proves in 12.4 s with 1.17 GB peak heap native — over the
   6 s prove limit [measured]. With 16 grinding bits the conjectured `R_TX` minimum is 173,812 B.
3. **Prover memory.** `R_TX` at the default needs 448.5 MB native peak heap and 452 MiB of wasm32 linear memory, over
   the 256 MiB hard limit of CTR-PQZ-18; blowup 8 fits (236 MiB) but its proof is 176 KB [measured].
4. **Zero knowledge costs about 2× in bytes and 4× in time and memory**: `R_TX` 253,294 B, 10.3 s native,
   2.0 GB [measured] (§6). The prototype's ZK mode had a bug (padding rows of the digit table), found and fixed here.

| `R_TX`, default parameters | Value | Limit | |
|---|---|---|---|
| Proof [measured] | 141,079 B (≈ 155 KB worst case over query positions [estimate], §4) | ≤ 160 KB (163,840 B), PQZH kind | met |
| Soundness [model] | 100.6 bits conjectured / 71.9 proven | 128 bits | **missed** (§7) |
| Prove, native, 1 thread [measured] | 2.57 s p50 / 2.62 s max | ≤ 6 s (CTR-PQZ-09) | met |
| Prove, wasm32 (node) [measured] | 4.43 s p50 / 4.75 s max | ≤ 5 s p95 browser (CTR-PQZ-18) | met under node, little margin |
| Verify, native [measured] | 8.2 ms p50, 11.0 ms p99 honest; 4.9 ms p99 adversarial | ≤ 50 ms p99 adversarial | met, 4.5× |
| Verify, wasm32 [measured] | 12.2 ms p50, 15.6 ms p99 honest; 6.0 ms p99 adversarial | — | |
| Prover memory [measured] | 448.5 MB peak heap native, 452 MiB wasm linear memory | ≤ 128 MiB budget, 256 MiB hard | **missed** |
| Verifier memory [measured] | 9.2 MB peak heap | — | |
| Module size [measured] | 1,674,605 B wasm, 498,643 B gzip −9 (prover + verifier + bench setup) | ≤ 1.0 MB gzip | met |
| Statement bytes vs pqz-core [measured] | byte-identical (`R_REG`, `R_TX`, statements and witnesses) | — | §8 |

**Answer to the sweep question** [model + measured]: no setting in the grid (blowup 2–32, FRI arity 2–16, 16 or 24
grinding bits, Goldilocks² or ⁵) meets ≥ 128 bits **provable** within 160 KB, for `R_TX` (≥ 288,945 B, 1.8× the
limit) or `R_REG` (≥ 214,496 B). ≥ 128 bits **conjectured** within 160 KB: `R_REG` at several settings (from
117,501 B); `R_TX` only at Goldilocks⁵ / blowup 32 / 21 queries / 24 grinding bits (160,813 B), which misses the
prove-time and memory limits. Levers not yet measured are in §9.

## 2. What ran

| Item | Value |
|---|---|
| Machine | AMD Ryzen 5 7235HS (Zen 3+), single thread, other services running; every timed run alone under `scripts/capped` (machine-wide lock, 4 GB cap) |
| Toolchain | Rust 1.97.1 (pinned, `pqz-core/pqzh/rust-toolchain.toml`; Plonky3 0.8.0 does not build on 1.90), target `wasm32-unknown-unknown`; node v26.8.1; clang 18 for pqz-core |
| Crates | Plonky3 `=0.8.0` (`p3-batch-stark`, `p3-uni-stark`, `p3-fri`, `p3-lookup`, `p3-goldilocks`, `p3-keccak`, `p3-merkle-tree`, `p3-security`, …), `sha3 =0.10.8`, `postcard =1.1.1`; no `parallel` feature (no rayon), no getrandom |
| Configuration | Goldilocks, challenge field Goldilocks² (Goldilocks⁵ with `Params::ext5`); `TwoAdicFriPcs` (plain) / `HidingFriPcs` with 4 random codewords (ZK); Merkle trees of Keccak-f (`PaddingFreeSponge<KeccakF>`, 32-byte digests, no cap), Keccak-256 challenger seeded with `SHAKE256("SCAAS-PQZH-TRANSCRIPT-V1" ‖ op ‖ be32(len) ‖ stmt)`; final polynomial 8 coefficients, grinding only before the queries |
| Inputs | `client::setup()`: the same keys, ciphertexts, statements and witnesses as pqz-core's `test/pqz_bench.c` `setup()` (§8) |
| Runs | `runs/rerun-all.sh` reruns everything below; native bench `runs/bench.sh` (`/usr/bin/time -v`), wasm32 `wasm/run_wasm.mjs`, sweep `pqzh_security`, `xcheck/run.sh`; raw JSON lines in `runs/` (file names below) |
| Statistics | p50 / p99 over the stated n; prove n = 10 native, 5 wasm; verify n = 200 native, 100 wasm; adversarial 12 kinds × 20 (native) / × 10 (wasm). For n ≤ 3 only p50 / max are meaningful |

## 3. What was built

Design D1 of `pqzh-design.md` §3 (challenge-free, NTT domain), as one `p3-batch-stark` proof over four AIRs
(`src/air.rs`):

| AIR | Rows | Width | What it does |
|---|---|---|---|
| `Poly` | 64 per witness polynomial (`R_REG` 96 polys → 2^13, `R_TX` 196 → 2^14) | 72 | row k holds the negacyclic rotation X^−k·w, so column 0 is coefficient w[k] (range-checked once) and `NTT(w)[k]` is a fixed linear form of the row (periodic weights); exact ℓ2 norms accumulate column 0 squared per group and end in a range-checked slack |
| `Mv` | (group, NTT point, input): `R_REG` 2^14, `R_TX` 2^15 | 3 + 9 outputs | every ring identity pointwise at the 64 NTT points: the inputs' NTT values arrive on a permutation bus, one accumulator per output must hit the public target at the block end |
| `Digit` | 16 (128 in ZK mode) | 30 | `R_TX` rows 3–7 per digit index: the three `v` identities with quotients, `M` and `e_T` limbs, the carry chain, `e2` ℓ2 norms; the statement-product coefficients arrive on a second bus |
| `Range` | 2^13 | 2 | the LogUp table 0..8191 for every range check (coefficients ± offset, quotients, limbs, slacks) |

Two departures from the study [inference: both cut the proof]: **public data in periodic columns** instead of
preprocessed commitments and a public-memory argument — `NTT(A)` and the statement coefficients are periodic columns
that prover and verifier both compute and the verifier evaluates at the out-of-domain point itself, so nothing of them
is in the proof (the verifier pays 1.2 ms / 2.7 ms to build them, the `empty`-proof time in §4); and **one `Mv` AIR**
for all identities, stacked in groups of 9 outputs so its opened width stays 12 however many outputs there are. The
honest prover checks the witness norms and refuses; `prove_unchecked` skips that so the tests can push out-of-range
witnesses into the proof system. `verify` bounds the proof length (160 KB) before parsing, rejects trailing bytes and
any `degree_bits` other than the ones the statement implies, never reads FRI parameters from the proof, and turns a
panic into 0.

Tests (`runs/s1-all-tests.txt`, all pass [measured]): `tests/attacks.rs` (6) — honest proofs verify and are
≤ 160 KB; wrong op, swapped proofs and other FRI parameters are rejected; a key with every |s_k| ≤ 1 but ‖s‖² = 1300 >
36² (only the exact ℓ2 check catches it), a coefficient of 100, an amount digit of 23 with a compensating carry,
‖e2‖ = 65 > 64 and an overspend (new-balance digits all 15) each yield no proof or a proof that does not verify;
`tests/smoke.rs` (2) — honest plain and ZK proofs; ring NTT unit tests (2).

## 4. Native results

`runs/s2-native.jsonl`, `runs/s2-native-time.txt` [measured]:

| Default parameters | `R_REG` | `R_TX` |
|---|---|---|
| Proof | 110,388 B | 141,079 B |
| Prove p50 / max (n = 10) | 1.22 s / 1.37 s | 2.57 s / 2.62 s |
| Prove peak heap | 223.2 MB | 448.5 MB (process max RSS 466 MB) |
| Verify honest p50 / p99 (n = 200) | 4.2 / 5.9 ms | 8.2 / 11.0 ms |
| Verify adversarial p50 / p99 (n = 240) | 1.7 / 2.8 ms | 3.4 / 4.9 ms |
| Mutated inputs accepted / verifier panics | 0 / 0 of 240 | 0 / 0 of 240 |
| Verify peak heap | 4.7 MB | 9.2 MB |

The twelve mutation kinds (`client::mutate`): one bit flipped, one byte changed, random bytes of the valid length,
truncated, extended, a statement coefficient +1 mod q, a coefficient ≥ q (non-canonical, rejected before any proof
work), the 64-byte prefix (opTag / `proofSystemId`), the message (`R_REG`) or the fee (`R_TX`), a valid proof of
another statement, a non-canonical field element, the empty proof. A mutated input is rejected at or before the
out-of-domain check, so adversarial verifies are cheaper than honest ones; the worst case is the honest path,
11.0 ms p99 for `R_TX` [measured], ≈ 1.3 M gas at 0.12 M gas/ms [estimate].

Where the `R_TX` bytes go (`rel::breakdown`) [measured]:

| Part | Bytes | Share |
|---|---|---|
| Opened rows of the three trace commitments (main 26,125, LogUp 2,885, quotient 10,893) | 39,903 | 28.3 % |
| Merkle paths of those three commitments | 41,621 | 29.5 % |
| FRI: 6 folding layers (siblings 10,926 + Merkle paths 42,506), commitments 238, final polynomial 129 | 53,799 | 38.1 % |
| Out-of-domain values | 5,483 | 3.9 % |
| Commitments, LogUp terminals | 184 | 0.1 % |

Merkle paths are 60 % of the proof. **The size depends on the query positions** (paths that share nodes are sent
once): the same parameters gave 143,965 B before an AIR change that left the shape alone, 141,079 B after. Without
any sharing the 28 paths of depth 19 would add ≈ 9.5 KB to the trace openings and ≈ 4 KB to FRI, so the worst case
at the default is ≈ 155 KB [estimate]; a limit has to hold for the worst case, not a sample [inference].

Blowup 8 / 38 queries (`runs/s3-native-b8q38.jsonl`) halves prover time and memory — `R_TX` 1.50 s, 233 MB; `R_REG`
0.76 s, 116 MB — but `R_TX` grows to 176,114 B, over 160 KB [measured].

## 5. wasm32

The crate builds for `wasm32-unknown-unknown` unchanged: Plonky3 0.8.0 needs no clock, randomness or threads; the
module (`wasm/`: raw C-ABI exports, no wasm-bindgen, `panic = "abort"`, LTO) imports nothing. Proofs are
byte-identical to native for the same inputs (FNV-1a `R_REG` `92e21939`, `R_TX` `aeb378b3` at the default;
`d556d7a5` / `d20a5f27` at blowup 8) [measured]. `runs/s3-wasm.jsonl`, `runs/s3-wasm-b8q38.jsonl` (node v26.8.1):

| wasm32, node [measured] | `R_REG` | `R_TX` |
|---|---|---|
| Prove p50 / max (n = 5) | 2.14 s / 2.41 s | 4.43 s / 4.75 s |
| Verify honest p50 / p99 (n = 100) | 6.3 / 8.4 ms | 12.2 / 15.6 ms |
| Verify adversarial p50 / p99 (n = 120) | 1.8 / 3.3 ms | 4.0 / 6.0 ms |
| Linear memory high-water after proving | 225.6 MiB | 452.1 MiB |
| Same, blowup 8 / 38 queries (n = 2) | 118.4 MiB, 1.64 s | 236.3 MiB (254.1 after verify), 2.54 s; proof 176 KB, over the limit |

wasm32 is ≈ 1.7× native for proving and ≈ 1.5× for verifying. Memory binds: at blowup 16 `R_TX` needs 1.8× the
256 MiB hard limit; blowup 8 fits the hard limit but not the 128 MiB budget, and breaks the proof limit. Linear memory
never shrinks, so its high-water mark is what a browser tab must grant [inference]. With `panic = "abort"` a verifier
panic would trap instead of returning 0; none occurred in the 480 native mutated verifies (the bench counts panics
caught by `verify`), but a node-side verifier should run native, as planned (`pqzh-design.md` §6) [inference].

## 6. Zero-knowledge mode

`Params::zk` switches to `HidingFriPcs` (4 random codewords, salted Merkle leaves, both seeded from the prover's 32
random bytes) and the batch prover's randomisation polynomial; the `Digit` table is padded from 16 to 128 rows for the
hiding PCS's masking budget (`rel::digit_height`). From the Plonky3 sources, every non-preprocessed commitment (main
traces, LogUp traces, quotient chunks) gets random rows interleaved (the committed domain doubles) and random columns;
the periodic public data is never committed, so nothing public needs hiding [inference from the source, not audited].

**Bug found and fixed** (commit `6e640c7`): the padding rows of the `Digit` table were all zero, which violates row 6
(`e_T + 2^24 = etlo + 8192·ethi`), so every ZK `R_TX` proof failed to verify; and the carry-out constraint sat on the
table's last row — row 127 in ZK mode — so unconstrained padding rows could have continued the carry chain past
digit 15. Padding rows now carry `e_T = 0`, and the carry out of digit 15 is pinned by a periodic selector in both
modes. `tests/smoke.rs::zk_honest_and_hiding` (two hiding proofs of one statement differ, both verify, a flipped byte
and the plain verifier reject them) passes under the `checked` profile, which checks every constraint and lookup of
the traces [measured, `runs/s4-smoke-zk.txt`]. Plain-mode proofs were unaffected in soundness (16 rows, no padding).

| Default parameters + ZK [measured], `runs/s4-native-zk.jsonl`, `runs/s4-wasm-zk.jsonl` | `R_REG` | vs plain | `R_TX` | vs plain |
|---|---|---|---|---|
| Proof | 195,134 B | +77 % | 253,294 B | +80 % |
| Prove p50, native (n = 10) | 5.25 s | 4.3× | 10.34 s | 4.0× |
| Prove peak heap, native | 1,062 MB | 4.8× | 2,012 MB (RSS 2.08 GB) | 4.5× |
| Verify honest p50 / p99, native | 5.2 / 7.6 ms | +25 % | 9.0 / 11.6 ms | +10 % |
| Verify adversarial p99, native | 3.8 ms | | 6.1 ms | |
| Prove p50, wasm32 (n = 3) / linear memory | 9.37 s / 1,067 MiB | | 18.9 s / 2,018 MiB | |

Both relations are over 160 KB in ZK mode (`verify` ran with the limit lifted, `--max-proof`). Soundness [model,
`runs/s6-model-ext2-zk.jsonl`]: the committed domain is one bit longer and the quotient has 8 chunks, so the
Goldilocks² cap falls to 98.9 bits (`R_TX`); over Goldilocks⁵ the same query counts as in plain mode reach 128 bits
(`runs/s6-model-ext5-zk.jsonl`) — Goldilocks⁵ with ZK is not built.

## 7. Soundness sweep

`src/bin/pqzh_security.rs` feeds `p3-security` 0.8.0 (Plonky3's calculator: the round-by-round bounds of ePrint
2024/1553, the Johnson-regime bound of ePrint 2026/2056, the "random words" conjectured regime of ePrint 2025/2010, a
LogUp fingerprint term) with the real shapes of the batch, taken from the calls `ProverData` / `prove_batch` make:
constraints summed over the AIRs (`R_REG` 120, `R_TX` 158, LogUp's included), maximum constraint degree 3, 2 quotient
chunks, the largest committed domain (2^14 / 2^15 rows), batched opening columns (`R_REG` 216, `R_TX` 340 over
Goldilocks²; 282 / 502 over Goldilocks⁵), 4 LogUp interactions per row of width ≤ 2, Keccak's 128-bit collision bound.
"Proven" is the better of the unique-decoding and the Johnson list-decoding regime; "conjectured" is the random-words
regime (Plonky3's replacement for the up-to-capacity conjecture disproved in ePrint 2025/2046). With `--measure` the
sweep proves at the smallest query count that reaches the target and records the bytes.

**Goldilocks² (as built)** [model, `runs/s6-model-ext2.jsonl`]:

| Blowup | Ceiling at any query count, `R_TX` / `R_REG` (proven = conjectured) | Binding term | Default 28 queries, `R_TX`: proven / conjectured |
|---|---|---|---|
| 2 | 103.6 / 105.3 | opening batching | 30.0 / 43.2 |
| 4 | 102.6 / 104.3 | opening batching | 44.0 / 70.9 |
| 8 | 101.6 / 103.3 | opening batching | 58.0 / 98.6 |
| 16 | 100.6 / 102.3 | opening batching | **71.9 / 100.6** |
| 32 | 99.6 / 101.3 | opening batching | 83.6 / 99.6 |

The opening-batching round combines every committed column (340 for `R_TX`) over the LDE domain (2^19 at blowup 16)
with one challenge from a 2^128 field: `(k − 1)·n / |F|` ≈ 2^−100.6. Grinding at that round would lift it, but then
FRI's commit phase binds at 105–110 bits even with 24 grinding bits at the batching, out-of-domain and LogUp rounds
(`runs/s6-model-ext2-grind24.jsonl`) [model]. Goldilocks² cannot give 128 bits in either regime for this AIR [model].
At 100 bits (`runs/s6-measure-ext2-t100.jsonl`): conjectured `R_TX` 119,327 B (blowup 16, arity 16, 22 queries),
proven 412,408 B (blowup 16, arity 8, 93 queries) [measured sizes].

**Goldilocks⁵** (`Params::ext5`, built and verified), 128 bits, FRI arity 8, `runs/s6-measure-ext5.jsonl` (16
grinding bits) and `runs/s6-measure-ext5-pow24.jsonl` (24); arity 2 / 4 / 16 are in the files — 4 and 8 are within
±3 % of each other, 2 and 16 larger:

| Blowup | Proven: queries (16 / 24 bits) | `R_TX` 16 / 24 bits | `R_REG` 16 / 24 bits | Conjectured: queries (16 / 24) | `R_TX` 16 / 24 bits | `R_REG` 16 / 24 bits |
|---|---|---|---|---|---|---|
| 2 | 225 / 209 | 1,030,421 / 968,449 B | 728,619 / 680,995 B | 114 / 106 | 554,710 / 520,176 B | 396,004 / 373,687 B |
| 4 | 113 / 105 | 588,447 / 547,522 B | 424,393 / 393,160 B | 57 / 53 | 323,843 / 303,162 B | 233,108 / 217,654 B |
| 8 | 75 / 70 | 428,317 / 402,746 B | 312,751 / 291,728 B | 38 / 35 | 234,831 / 224,024 B | 172,811 / 164,131 B |
| 16 | 57 / 53 | 355,513 / 334,740 B | 258,139 / 242,868 B | 29 / 27 | 199,884 / 187,254 B | 147,215 / 139,653 B |
| 32 | 45 / 42 | 305,252 / **290,190 B** (288,945 at arity 4) | 224,896 / **214,496 B** | 23 / 21 | 173,812 / **160,813 B** | 130,894 / **117,501 B** |

Costs of the two corners [measured]: Goldilocks⁵, blowup 16, 57 queries (128 proven): `R_TX` 3.4 s prove, 595 MB peak
heap, 14.8 ms verify (single runs, before the §6 fix, which does not change the plain-mode work). Goldilocks⁵, blowup 32, 21 queries, 24 grinding bits (128 conjectured, the only
`R_TX` setting under 160 KB; `runs/s7-ext5-b32-q21-pow24.jsonl`): `R_TX` 160,813 B, prove 12.4 s p50, 1,169 MB peak
heap, verify 13.1 ms p50 / 17.1 ms p99; `R_REG` 117,501 B, 6.75 s, 588 MB [measured].

**Flag:** no setting in the grid meets ≥ 128 bits **provable** within 160 KB, for either relation. ≥ 128 bits
**conjectured** within 160 KB: `R_REG` from blowup 16 (147,215 B at 29 queries, 16 bits); `R_TX` only at the corner
above, 3 KB under the limit on one sample of query positions, and over the prove-time (6 s) and memory limits
[model + measured].

## 8. Cross-check with pqz-core

`xcheck/run.sh` builds pqz-core (`build.sh native`), compiles `xcheck/dump_setup.c` (pqz-core's `test/pqz_bench.c`
included whole, its `setup()` run through `step_init`) and the Rust `examples/dump_setup.rs` (`client::setup()`), and
compares the four buffers byte for byte [measured, `runs/s5-xcheck.txt`]:

| Buffer | Bytes | SHA-256 (first 16 hex), C = Rust |
|---|---|---|
| `R_REG` statement | 16,480 | `c0bc5d9af68ab5eb` |
| `R_REG` witness | 6,144 | `17c7a9f62fa77af1` |
| `R_TX` statement | 82,504 | `2e48c8b1d233c26b` |
| `R_TX` witness | 12,416 | `258e15b72416daa6` |

So PQZH proves exactly pqz-core's statements: same `A` (SHAKE128 expansion), key generation, encryption, digit
encoding and byte layout. The check is against this branch's pqz-core, i.e. the spike `R_TX` layout (64-byte prefix,
`be8(fee)` at the end). The relation fix-ups on `pqz-relfix` move `R_TX` to the §7.7 debit layout (640-byte header,
fee at offset 256); `rel.rs::parse_tx` and `client.rs` have to follow when that merges, and the cross-check is rerun.

## 9. What could close the gaps

[inference unless marked]

- **Soundness needs a bigger challenge field.** Goldilocks⁵ already works in the prototype. At about the same query
  count it costs ≈ 40 % more bytes (`R_TX` blowup 16: 199,884 B at 29 queries vs 141,079 B at 28 over Goldilocks²),
  because out-of-domain values, LogUp and quotient openings and FRI siblings are extension elements [measured sizes].
- **Proof bytes.** Merkle paths are 60 %: a Merkle cap (`cap_height` 4–6) drops the top levels every query shares;
  fewer committed columns shrink the opened rows (the 72-wide `Poly` rows are ≈ 16 KB, 11 % of `R_TX`); WHIR (Plonky3 has a
  `WhirPcs`) needs fewer queries for the same bits (`pqzh-design.md` §5.5). None measured here.
- **Batching term.** Fewer batched columns or a smaller domain lift the Goldilocks² ceiling by a few bits each; it
  does not reach 128.
- **Memory and time.** The prover keeps every LDE and Merkle tree alive (448 MB at blowup 16; 1.2 GB at blowup 32
  over Goldilocks⁵). Shorter traces (wider rows), a lower blowup, or committing in chunks would be needed for 256 MiB,
  each against the proof limit.
- **The limit.** At 128 bits proven a realistic FRI `R_TX` proof is ≈ 290–310 KB; at 128 bits conjectured
  ≈ 160–175 KB. The precompile's `MAX_INPUT` (262,144 B) holds an `R_TX` proof up to ≈ 179 KB (`pqzh-design.md` §5.6):
  conjectured fits it, proven does not.

## 10. Open questions for the owner

1. **Soundness target for PQZH**, given the measurements: 128 bits proven (`R_TX` ≈ 290 KB: needs a higher proof limit
   and precompile `MAX_INPUT`), 128 bits conjectured (≈ 161–174 KB; 160 KB only with blowup 32 and 24 grinding bits,
   12 s prove), or ≈ 100 bits on Goldilocks² within 160 KB? The owner leaned provable; no provable setting fits 160 KB.
2. **Goldilocks⁵ as the PQZH challenge field** (needed for 128 bits in either regime under Plonky3's calculator)?
3. **Memory**: accept native-only proving for PQZH (448 MB plain, 2 GB ZK) or hold the 256 MiB browser limit, which
   needs layout work before the proof limit can be judged?
4. **Zero knowledge** doubles the proof and quadruples prove time and memory. Is it required for PQZH (balances and
   amounts are hidden by MLWE either way; the question is what a non-hiding proof leaks about the witness — keys,
   encryption randomness, digits), or can PQZH run without it?
5. **Next measurements before the limit is set**: Merkle caps and a WHIR commitment for the proof size, a layout for
   memory?

## 11. Reruns

From `pqz-core/pqzh/`, each heavy command alone under the machine lock (`scripts/capped` is the repository's):

```sh
scripts/capped runs/rerun-all.sh            # every run of this note, in order (≈ 35 min)
# or one at a time:
scripts/capped cargo test --release --offline                                        # §3
scripts/capped runs/bench.sh s2-native --np 10 --nv 200 --nadv 20                    # §4
(cd wasm && scripts/capped cargo build --release --offline --target wasm32-unknown-unknown)
scripts/capped node wasm/run_wasm.mjs 5 100 10        # §5 (args: np nv nadv log_blowup queries zk max_proof)
scripts/capped runs/bench.sh s4-native-zk --zk --np 10 --nv 200 --nadv 20 --max-proof 1000000   # §6
scripts/capped xcheck/run.sh                                                         # §8
scripts/capped target/release/pqzh_security --ext 5 --measure > runs/s6-measure-ext5.jsonl     # §7
python3 runs/sweep-summary.py runs/s6-measure-ext5.jsonl
```
