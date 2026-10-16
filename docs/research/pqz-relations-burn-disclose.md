> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ relations `R_BURN`, `R_DS`, `R_DR`: burn / refresh and disclosure proofs in `pqz-core` (P6)

Written 2026-10-13 for the owner's request to measure the three PQ Zether relations that the E-S1 spike
(`pqz-core-e-s1.md`) left out: `R_BURN` (`OP_BURN`, also `REFRESH`), `R_DS` (`OP_DISCLOSE_SENDER`) and `R_DR`
(`OP_DISCLOSE_RECEIVER`, also the auditor). Question: what do they cost with the generic LaZer verifier, against
CTR-PQZ-09 (proof ≤ 96 KB, p99 verify ≤ 50 ms, prove ≤ 6 s desktop) and the browser budgets of CTR-PQZ-18? Code on
branch `pqz-rel3` (merged, `3ad4069`): `pqz-core/params/{burn,ds,dr}_params.sage` and the generated headers,
`pqz-core/src/pqz_rel.c`, `pqz-core/test/pqz_bench.c`, runs `pqz-core/rel3/`. The owner's answers to the questions of
§5 (2026-10-13) were built on branch `pqz-relfix` ("the fix-ups"); §1 and §4 give the numbers after them, with the
change from the first run. **No decision is recorded here** (the decisions are in pq-zero-knowledge.md and decisions.md).

**[measured]** marks a number from a run in this note (machine in §2). **[estimate]** marks a number computed from
counts or a rough figure. **[inference]** marks a conclusion drawn here.

## 1. Result

**All three relations prove and verify through the existing `pqz_prove` / `pqz_verify` API, reject every tampered
input tried, and fit the proof-size and prove-time limits with room; like `R_TX`, they miss the 50 ms p99 verify
limit with the generic verifier (4.4× to 12.5×) [measured].** `R_BURN` costs about what `R_TX` costs (it is `R_TX`
without two of its seven row groups); the two disclosure relations cost about what `R_REG` costs.

| Generic verifier, after the fix-ups, `proofSystemId` v2 [measured] | proof bytes | prove p50 / p99 native | verify p50 / p99 native | p99 adversarial native | prove p50 wasm | verify p50 / p99 wasm | arena peak native / wasm, one op |
|---|---|---|---|---|---|---|---|
| `R_BURN` | 41,916–41,940 | 749 / 1,197 ms | 536 / 627 ms | 560 ms | 982 ms | 714 / 751 ms | 289 / 220 MB |
| `R_DS` | 28,936–28,976 | 292 / 337 ms | 199 / 247 ms | 226 ms | 489 ms | 271 / 284 ms | 100 / 77 MB |
| `R_DR` | 28,988–28,999 | 311 / 403 ms | 202 / 222 ms | 231 ms | 462 ms | 270 / 281 ms | 108 / 83 MB |
| for reference: `R_TX` | 42,741–42,770 | 1,007 / 1,111 ms | 638 / 721 ms | 675 ms | 1,566 ms | 809 / 878 ms | 304 / 232 MB |
| for reference: `R_REG` | 28,097–28,108 | 235 / 321 ms | 158 / 212 ms | 180 ms | 387 ms | 216 / 232 ms | 96 / 74 MB |

Run `v2full` (`rel3/relfix.sh v2full` on main after the `pqz-v2` merge, 2026-10-13; the same sample sizes as
`f2`, §2). Native: `pqz_bench 10 100 31` (10 proves, 100 + 100 honest verifies, 126 adversarial per relation, all
five relations); wasm32 under node: `run_wasm.mjs 5 30 31` (5 proves, 30 + 30 honest, 42
adversarial). Proof bytes: the last and the largest of the native seeds. "Arena peak, one op" is the high-water mark of
a process that runs only that relation (`v2full-alone.jsonl`), i.e. what a prover for that op carries: since the fix-ups a
relation's keys are built at its first use (§4). Each relation's first prove includes building its keys.

| Against CTR-PQZ-09 / CTR-PQZ-18 (after the fix-ups, v2) | `R_BURN` | `R_DS` | `R_DR` |
|---|---|---|---|
| proof ≤ 96 KB (98,304 B) | 42.7 % of the limit | 29.5 % | 29.5 % |
| prove ≤ 6 s desktop (native p99) | 1.20 s, inside | 0.34 s, inside | 0.40 s, inside |
| p99 verify ≤ 50 ms (native, honest or adversarial, the larger; generic verifier) | 627 ms, **12.5× over** | 247 ms, **4.9× over** | 231 ms, **4.6× over** |
| browser prove 5 s desktop / 15 s phone / 30 s hard (wasm, node, max of 5) | 1.10 s, inside | 0.65 s, inside | 0.65 s, inside |
| browser memory 128 MiB budget / 256 MiB hard (wasm arena peak, one op) | 210 MiB: over the budget, inside the hard limit | 73 MiB, inside | 79 MiB, inside |

**`R_TX0`, the transfer without the auditor (P6e Task 2, 2026-10-14; CTR-PQZ-24, plan D8 / R6).** `R_TX` without
`pk_a`, `v_a`, `e2_a` (row 5 skipped), op 1 with a 66,560-byte statement; the `auditorOn` header word must say the same
as the length; its own ABDLOP keys (tag byte 0x81). Run `tx0c` (`rel3/runs/tx0c-*`, `sv/runs/tx0c-*`; the earlier runs
`tx0`, `tx0b` are kept; `pqz-core/STATUS.md` has the full record) [measured]:

| `R_TX0` | proof bytes | prove p50 / p99 native | verify p50 / p99 native (generic) | p99 adversarial native | prove p50 wasm | verify p50 wasm (generic) | SV p50 / p99 portable, x86-64-v3, wasm | arena peak native / wasm, one op |
|---|---|---|---|---|---|---|---|---|
| `R_TX0` | ≤ 42,441 | 827 / 1,128 ms | 577 / 627 ms | 627 ms | 1,398 ms | 760 ms | 8.03 / 8.49, 4.68 / 5.53, 13.4 / 14.7 ms | 298 / 227 MB |

Sizing (`pqz-core/params/estimator-e-s1-tx0.txt`): MSIS(23, 213, 2^35.96) β 457 (2^133.4 / 2^121.1), MLWE(33, 35) uSVP
β 470, knowledge error ≤ 2^−127; within noise of `R_TX`, as expected for one key and one ciphertext slot fewer.

The 50 ms verify limit is met by the specialised verifier (`pqz-specialised-verifier.md` §0: p99 ≤ 11.1 ms portable,
≤ 16.0 ms wasm32 for all five relations on v2), not by the generic one above.

**Change from the first run** (`r1`, branch `pqz-rel3`, before the fix-ups; `R_REG` / `R_TX` from `r1-fnv-*` against
`f2-fnv-*`, the same 5 native / 3 wasm proves) [measured]:

| Before → after | `R_TX` | `R_BURN` | `R_DS` | `R_DR` | `R_REG` |
|---|---|---|---|---|---|
| proofs (`proofs_fnv`, native) | changed by design: `cb562b47` → `4690aaa0` | unchanged, `3289ff3e` | changed by design: `a6adc624` → `b6e547db` | changed by design: `92958731` → `d66d665a` | unchanged, `12ec7452` |
| proof bytes (native) | 42,734–42,770 → 42,734–42,772 | 41,916–41,939, same | 28,936–28,976 → 28,937–28,975 | 28,988–28,999 → 28,987–29,001 | 28,107, same |
| prove p50 native | 1,082 → 1,011 ms | 818 → 683 ms | 263 → 271 ms | 326 → 295 ms | 259 → 331 ms |
| verify p50 native | 701 → 634 ms | 561 → 526 ms | 208 → 195 ms | 198 → 194 ms | 167 → 187 ms |
| p99 verify native (the larger) | — | 664 → 624 ms | 244 → 221 ms | 229 → 232 ms | — |
| prove p50 / verify p50 wasm | 1,631 / 785 → 1,689 / 859 ms | 1,006 / 707 → 973 / 664 ms | 404 / 286 → 410 / 263 ms | 467 / 262 → 447 / 252 ms | 458 / 212 → 407 / 260 ms |
| arena peak per op native / wasm | 344 / 263 → 304 / 232 MB | 327 / 251 → 289 / 220 MB | 144 / 112 → 100 / 77 MB | 168 / 126 → 108 / 83 MB | 139 / 108 → 96 / 74 MB |

Sizes and times do not change beyond the per-seed spread and the host noise (±20 %): the equations are the same, and
`R_BURN`'s proofs are byte-identical, so its lower prove p50 is noise [inference]. `R_TX`, `R_DS` and `R_DR` prove
other bytes because their statements changed (§5 points 1, 2), and the transcript hashes the whole statement. What
changes is memory: every op drops the keys of the relations it does not use, 38–60 MB native / 30–43 MB wasm; wasm
`R_TX` 251 → 221 MiB, from 2 % to 13.6 % under the 256 MiB hard limit, and `pqz_init` 212 → 10 ms native, 292 → 26 ms
wasm (§4) [measured].

The verify misses are the same finding as for `R_TX` (`pqz-core-e-s1.md` §11, `pqz-verifier-floor.md`): the cost is
LaZer's generic `tbox` machinery, not the statements [inference]. node is not a browser and the budgets are about p95,
not medians (as in the E-S1 note).

## 2. What ran

| Item | Value |
|---|---|
| Machine | AMD Ryzen 5 7235HS (Zen 3+), single thread, other services running (the host is noisy, ±20 %) |
| Toolchain | clang 18.1.3 `-O2` portable (no `-march`), wasm-ld 18, node v26.8.1 |
| Runs | Before the fix-ups: `scripts/capped pqz-core/rel3/bench.sh r1`: `./build.sh all`, KAT, the `R_REG` / `R_TX` proof hashes, then the timings. After: `scripts/capped pqz-core/rel3/relfix.sh f2`: build, KAT, proof hashes of all five relations, the arena peak of each relation alone (one process per relation), ASan + UBSan, then the timings of all five. Raw JSON lines and the build / KAT logs in `pqz-core/rel3/runs/` (`f1-*`: an earlier fix-up run stopped before its timings) |
| Parameters | `params/{burn,ds,dr}_params.sage` → `params/pqz_{burn,ds,dr}_params.h` by `params/codegen/run.sh` (LaZer `3330e48`, pinned Sage image, ≈ 1 min each) |
| Statistics | p50 / p99 over the stated number of runs on one machine; the bench's p99 is the 99th-percentile element of the sorted sample |

## 3. The relations

All three are LaZer `tbox` statements over the same ring and modulus as `R_REG` / `R_TX` (q = 2^42 − 215, d = 64,
l = 4), written the way `build_reg` / `build_tx` write theirs: R_q-linear rows as quadratic equations without a
quadratic part, single-coefficient rows as `tbox` evaluation equations ct(X^−i·(…)) = 0, exact ℓ2 norm proofs per
witness block, one binary proof for all bits, and the one-poly approximate ℓ∞ filler LaZer's `tbox` needs.

| | `R_BURN` (pq-zero-knowledge.md §7.5) | `R_DS` (§7.9, `SENDER_S`) | `R_DR` (§7.9, `RECEIVER_X`, `AUDITOR`) |
|---|---|---|---|
| Equations | `R_TX` rows 1, 2, 4, 6, 7 with d = digits(amount) public: pk_f = A s_f + e_f; u = Aᵀr + e1; v_f[i] = (pk_fᵀr)[i] + e2_f[i] + Δ d′_i; v_T[i] − (u_Tᵀs_f)[i] = Δ M_i + e_T[i]; M_i + c_{i−1} = d′_i + d_i + f_i + 16 c_i | u = Aᵀr + e1; v[i] = (pkᵀr)[i] + e2_t[i] + Δ·digits(amount)_i | pk = A s + e; v[i] − (uᵀs)[i] = Δ·digits(amount)_i + e′_i |
| Rows | 64 R_q rows, 48 evaluation equations | 32 R_q rows, 16 evaluation equations | 32 R_q rows, 16 evaluation equations |
| Witness s1 (m1, + Z slack polys) | s_f, e_f, r, e1 (4 × 32 polys), e2_f (1), 14 binary polys (143 + 5) | r, e1 (2 × 32), e2_t (1) (65 + 3) | s, e (2 × 32), 7 binary polys (71 + 2) |
| Bits | d′ 64, M 224, c + 64 165, e_T + 2^24 400: 853 | none | e′ + 2^24: 16 × 25 = 400 |
| Exact ℓ2 bounds | 36, 164, 36, 164, 64 | 36, 164, 64 | 36, 164 |
| ℓ∞ filler | e2_f, bound 64 | e2_t, bound 64 | s[0], bound 1 |
| Codegen (MSIS / MLWE, D, γ, estimate) | MSIS(23, 211, 2^35.95), MLWE(33, 35); D 11, γ 704,254; ≈ 43,758 B | MSIS(22, 132, 2^35.31), MLWE(33, 34); D 7, γ 65,512; ≈ 30,084 B | MSIS(23, 139, 2^35.84), MLWE(33, 35); D 12, γ 1,408,508; ≈ 30,150 B |
| Knowledge error (codegen) | ≤ 2^−127 | ≤ 2^−127 | ≤ 2^−127 |
| Pinned estimator (`run_e_s1.sh … burn ds dr`): MSIS β / MLWE uSVP β, best attack classical / quantum | 457 / 470; 2^133.4 / 2^121.1 | 452 / 470; 2^132.0 / 2^119.8 | 461 / 470; 2^134.6 / 2^122.2 |

`R_BURN` shares the `R_TX` builder (`build_debit`): the same rows in the same order, with rows 3 and 5 skipped and the
public digits moved into the constant terms, and the bit layout of the remaining groups packed from slot 0. The
prover derives M, the carries and e_T by decrypting T with s_f, as for `R_TX`; the carry range and the proof that
Σ M_i 16^i = b′ + amount + fee are `R_TX`'s (the carries of honest states stay in [−3, 1093]). With amount = 0 the
same relation is `REFRESH` [inference]. `R_DR`'s prover derives e′_i = centre(v_i − (uᵀs)_i) − Δ·d_i and refuses if it
is outside the range. Each relation has its own ABDLOP keys (`SCAAS-PQZ-ABDLOP-PP-V1 ‖ op`), built at the relation's
first prove or verify since the fix-ups (§4, §5 point 5); `REFRESH` shares op 2's, `AUDITOR` op 5's. With the same
`pqz_delta` (1.00366) and MLWE rank floor as `R_REG` / `R_TX`, all three reach the CTR-PQZ-03 target β ≥ 450 on the
first try under lattice-estimator `53da598`, RC.ADPS16 (`params/estimator-e-s1-rel3.txt`) [measured]. The public
matrix A is expanded once at `pqz_init` and shared by all relations.

**Statements** (`pqz.h`), as pq-zero-knowledge.md lays them out:

| Op | Statement | Bytes | Read by the relation |
|---|---|---|---|
| 1 `OP_TRANSFER` (`R_TX`, auditor on; since the fix-ups, §5 point 1) | header (§7.7, 640 B) ‖ pk_f ‖ pk_t ‖ pk_a ‖ T = u_T ‖ v_T ‖ out = u ‖ v_t ‖ v_f ‖ v_a | 83,072 (= §7.7's transfer size) | fee (offset 256, be32 word < 2^64); keys, T, out |
| 2 `OP_BURN` | header (§7.7, 640 B) ‖ pk_f ‖ T = u_T ‖ v_T ‖ out = u ‖ v_f | 50,048 (= §7.7's burn size) | fee (offset 256) and amount (288), each a be32 word that must be < 2^64; pk_f, T, out |
| 4 `OP_DISCLOSE_SENDER`, 5 `OP_DISCLOSE_RECEIVER` | opTag ‖ proofSystemId ‖ chainId ‖ chainUid ‖ token ‖ registry ‖ entryRef ‖ amount ‖ kind ‖ pk ‖ u ‖ v, every scalar a 32-byte word (§7.9 offset table; since the fix-ups, §5 point 2) | 33,184 | amount (offset 224, < 2^64), pk (288), u, v |

Everything else in a statement is only hashed into the transcript (op and the whole statement are absorbed before any
prover message, as for `R_REG` / `R_TX`), so a proof is bound to it. Any coefficient ≥ q or an amount / fee word
≥ 2^64 makes the verifier return 0. Witness encodings follow `R_TX`'s (int8 for CBD(1) vectors, int16 LE for CBD(20)
ones): `R_BURN` s_f ‖ e_f ‖ r ‖ e1 ‖ e2_f ‖ d′ (12,336 B), `R_DS` r ‖ e1 ‖ e2_t (6,176 B), `R_DR` s ‖ e (6,144 B).

## 4. Checks

| Check | Result [measured] |
|---|---|
| Honest proofs verify | every run: native 10 + 200 verifies, wasm 5 + 60 per relation, all five relations (`f2`) |
| Tampered input rejected | six kinds: one proof bit flipped, random proof bytes, a statement key coefficient changed, proof truncated by one byte, long all-ones tail, a public scalar changed (kind 5: the burn / disclosure amount, the `R_TX` fee at header offset 256, the `R_REG` message); 126 native + 42 wasm per relation, 0 accepted (`fails 0` in every `f2` file) |
| Arithmetic-layer KAT | 19/19 cases equal to the upstream golden dump (`f2-kat.txt`) |
| Proof hashes (`proofs_fnv`) | `R_REG` unchanged: native 5 seeds `12ec7452`, wasm 3 seeds `3bc7e9b3`, as on main (P6d-2). `R_BURN` unchanged: native 10 seeds `3289ff3e`, wasm 5 seeds `13b973e1`. Changed by design, because the statement changed: `R_TX` native `cb562b47` → `4690aaa0`, wasm `834d6853` → `f1c3e7f6` (§5 point 1); `R_DS` / `R_DR` (§5 point 2) |
| Native and wasm give the same proofs | byte for byte: the wasm 5-seed hashes (`f2-wasm`) equal the native 5-seed hashes (`f2-fnv-native`) for all five relations, and the 1-seed hashes of `f2-alone` are equal too |
| ASan + UBSan (libc heap, `-DPQZ_DEBUG_MALLOC`; 1 prove, 1 + 6 verifies per relation) | `fails 0`, no ASan report; UBSan reports only the known upstream nits (zero-length VLAs at `lnp-tbox.c` 223 / 875 / 3451, null + 0 at `aes256ctr.c:339`; `pqz-core/STATUS.md` Open 4) (`f2-asan*`) |
| Symbol scan (`check_symbols.sh`) | native and wasm objects reference only `memcpy`, `memset`, `__stack_chk_fail`, `__stack_pointer` |

These hashes are `proofSystemId` v1. v2 (the LaZer `tbox` fixes [lazer#24](https://github.com/lazer-crypto/lazer/issues/24) /
[#25](https://github.com/lazer-crypto/lazer/issues/25), branch `pqz-v2`) changes the transcript and so every proof hash;
sizes, arena and times stay the same within noise. The v2 values: `pqz-core/STATUS.md`, runs `rel3/runs/v2-*` and `rel3/runs/v2full-*` (§1).

**Arena.** Before the fix-ups every relation's ABDLOP keys (A1, A2′, B′) were built at `pqz_init` below the arena base
mark and kept: base 54.5 MB native / 43.3 MB wasm, init 212 ms native / 292 ms wasm, and every op carried the keys of
all five relations; the three new relations had added ≈ 27 MB native / ≈ 21 MB wasm to the base (`R_REG` peak
112 → 139 MB native, 87 → 108 MB wasm; `R_TX` 316 → 344 MB native, 241 → 263 MB wasm), which put the wasm `R_TX` peak,
251 MiB, 2 % under the 256 MiB hard limit of CTR-PQZ-18 [measured]. Since the fix-ups (§5 point 5) `pqz_init` expands
only A (base 3.1 MB native / 2.5 MB wasm, init 10 ms / 26 ms), and a relation's keys are built at its first prove or
verify and then kept below the base mark [measured]. One relation per process (`f2-alone.jsonl`) [measured]:

| Arena peak, one op | `R_REG` | `R_TX` | `R_BURN` | `R_DS` | `R_DR` |
|---|---|---|---|---|---|
| native, before → after | 139 → 96 MB | 344 → 304 MB | 327 → 289 MB | 144 → 100 MB | 168 → 108 MB |
| wasm, before → after | 108 → 74 MB | 263 → 232 MB | 251 → 220 MB | 112 → 77 MB | 126 → 83 MB |
| wasm after, against 128 MiB budget / 256 MiB hard | 70 MiB | 221 MiB, 13.6 % under the hard limit | 210 MiB | 73 MiB | 79 MiB |

A process that runs several relations keeps the keys of each one it has used: in the bench (`R_REG` to `R_DR` in
order) `R_TX` peaks at 312 / 238 MB and `R_BURN` at 310 / 237 MB [measured]. Arena release now also rebuilds the
size classes from the blocks that remain; without that a sequential `R_REG`, `R_TX`, `R_BURN` run filled the class
table and `R_BURN` peaked at 405 MB native instead of 310 MB [measured while fixing, not in `runs/`]. `R_DR`'s drop
(60 MB native) is more than the other relations' keys, so part of it is that rebuild [inference]. Not tried: keep only
the NTT form of the keys (LaZer holds both forms), or derive the keys per call (one `abdlop_keygen`).

## 5. Owner decisions (2026-10-13) and the fix-ups

The first version of this note left four choices open (statement layouts, what pqz-core checks, the disclosure noise
bound, the arena base). The owner answered on 2026-10-13 (points A, B, 1–5, all accepted as proposed); branch
`pqz-relfix` (merged `7e6e9b0`) carries B and 1–5 in code and in pq-zero-knowledge.md / decisions.md:

- **A. Merge `pqz-rel3`** (`R_BURN` / `R_DS` / `R_DR` with the generic verifier and the first version of this note)
  into main and push: done, `3ad4069`.
- **B. Burn / refresh randomness** is fresh CSPRNG output (hedging with the key seed allowed), never derived from the
  counter: their salt is 0, so two burns at one `sendCounter` would otherwise reveal `Δ·(b′ − b″)` (CTR-PQZ-19, §7.5,
  T12, a prover test in §14). No code change in pqz-core (the bench uses its test RNG; `R_BURN` proofs unchanged).
1. **`R_TX` on the §7.7 layout**: header (640 B) ‖ pk_f ‖ pk_t ‖ pk_a ‖ T ‖ out, fee as the be32 word at offset 256,
   83,072 B (was the E-S1 prefix ‖ … ‖ be8(fee)); the debit header is parsed by the code `R_BURN` uses. `R_TX` proofs
   change, sizes and times do not (§1).
2. **Disclosure `kind` is a 32-byte word**, so pk starts at 288; 33,184 B (was 33,153 B with a one-byte kind and pk at
   257); byte-offset table in pq-zero-knowledge.md §7.9. `R_DS` / `R_DR` proofs change, sizes and times do not (§1).
3. **The precompile checks opTag / proofSystemId** (pq-zero-knowledge.md §9.1); pqz-core does not repeat them, nor the `kind`:
   it reads only the fields its equations use, and those fields bind the proof because the whole statement is hashed
   into the transcript. `REFRESH` and `BURN` stay one relation under op 2, `RECEIVER_X` and `AUDITOR` one under op 5.
4. **The disclosure noise bound** reads e′_i ∈ [−2^24, 2^24), the range a 25-bit decomposition proves (was
   `abs(e′_i) < 2^24`); §4.3's e_T range and uniqueness bound (2^25 − 1 < Δ/2) are aligned to the half-open range. No
   code change.
5. **Keys at first use**: `pqz_init` expands A only; each relation's ABDLOP keys are built at its first prove or verify
   (§4). Every op's arena peak drops 38–60 MB native / 30–43 MB wasm; wasm `R_TX` 221 MiB [measured].

Still open, not asked: a disclosure bound of 2^14 (15 bits per coefficient instead of 25, binary witness 7 → 4 polys,
a few percent of the `R_DR` proof [estimate]) would be a spec change.

## 6. Reproduce

```sh
cd pqz-core
params/codegen/run.sh <LaZer 3330e48> params/burn_params.sage > params/pqz_burn_params.h   # also ds, dr
../scripts/capped rel3/relfix.sh <label>       # build all, KAT, proof hashes, arena per op, ASan + UBSan, timings
                                               #   of all five relations -> rel3/runs/<label>-*
build/native/pqz_bench 3 10 28                 # the three new relations only (bit mask 4 + 8 + 16)
```
