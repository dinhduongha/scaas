> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ relations `R_BURN`, `R_DS`, `R_DR`: burn / refresh and disclosure proofs in `pqz-core` (P6)

Written 2026-10-13 for the owner's request to measure the three PQ Zether relations that the E-S1 spike
(`pqz-core-e-s1.md`) left out: `R_BURN` (`OP_BURN`, also `REFRESH`), `R_DS` (`OP_DISCLOSE_SENDER`) and `R_DR`
(`OP_DISCLOSE_RECEIVER`, also the auditor). Question: what do they cost with the generic LaZer verifier, against
CTR-PQZ-09 (proof ≤ 96 KB, p99 verify ≤ 50 ms, prove ≤ 6 s desktop) and the browser budgets of CTR-PQZ-18? Code on
branch `pqz-rel3` (not merged): `pqz-core/params/{burn,ds,dr}_params.sage` and the generated headers,
`pqz-core/src/pqz_rel.c`, `pqz-core/test/pqz_bench.c`, runs `pqz-core/rel3/`. **No decision is recorded here.**

**[measured]** marks a number from a run in this note (machine in §2). **[estimate]** marks a number computed from
counts or a rough figure. **[inference]** marks a conclusion drawn here.

## 1. Result

**All three relations prove and verify through the existing `pqz_prove` / `pqz_verify` API, reject every tampered
input tried, and fit the proof-size and prove-time limits with room; like `R_TX`, they miss the 50 ms p99 verify
limit with the generic verifier (4.6× to 13×) [measured].** `R_BURN` costs about what `R_TX` costs (it is `R_TX`
without two of its seven row groups); the two disclosure relations cost about what `R_REG` costs.

| Generic verifier [measured] | proof bytes | prove p50 / p99 native | verify p50 / p99 native | p99 adversarial native | prove p50 wasm | verify p50 / p99 wasm | arena peak native / wasm |
|---|---|---|---|---|---|---|---|
| `R_BURN` | 41,916–41,939 | 818 / 1,062 ms | 561 / 664 ms | 614 ms | 1,006 ms | 707 / 790 ms | 327 / 251 MB |
| `R_DS` | 28,936–28,976 | 263 / 313 ms | 208 / 244 ms | 234 ms | 404 ms | 286 / 333 ms | 144 / 112 MB |
| `R_DR` | 28,988–28,999 | 326 / 372 ms | 198 / 229 ms | 229 ms | 467 ms | 262 / 307 ms | 168 / 126 MB |
| for reference: `R_TX` | 42,734–42,770 | 1,096 ms (5 runs) | 685 ms (5 runs) | 786 ms | 1,631 ms (3 runs) | 785 ms (1 run) | 344 / 263 MB |
| for reference: `R_REG` | 28,070–28,107 | 232 ms (5 runs) | 173 ms (5 runs) | 170 ms | 458 ms (3 runs) | 212 ms (1 run) | 139 / 108 MB |

Native: `pqz_bench 10 100 28` (10 proves, 100 + 100 honest verifies, 126 adversarial per relation); wasm32 under
node: `run_wasm.mjs 5 30 28` (5 proves, 30 + 30 honest, 42 adversarial). "Arena peak" is the high-water mark of the
arena including the tables built at `pqz_init` for all five relations (§4).

| Against CTR-PQZ-09 / CTR-PQZ-18 | `R_BURN` | `R_DS` | `R_DR` |
|---|---|---|---|
| proof ≤ 96 KB (98,304 B) | 42.7 % of the limit | 29.5 % | 29.5 % |
| prove ≤ 6 s desktop (native p99) | 1.06 s, inside | 0.31 s, inside | 0.37 s, inside |
| p99 verify ≤ 50 ms (native, honest or adversarial, the larger) | 664 ms, **13× over** | 244 ms, **4.9× over** | 229 ms, **4.6× over** |
| browser prove 5 s desktop / 15 s phone / 30 s hard (wasm, node, max of 5) | 1.17 s, inside | 0.50 s, inside | 0.70 s, inside |
| browser memory 128 MiB budget / 256 MiB hard (wasm arena peak) | 239 MiB: over the budget, inside the hard limit | 106 MiB, inside | 120 MiB, inside |

The verify misses are the same finding as for `R_TX` (`pqz-core-e-s1.md` §11, `pqz-verifier-floor.md`): the cost is
LaZer's generic `tbox` machinery, not the statements [inference]. node is not a browser and the budgets are about p95,
not medians (as in the E-S1 note).

## 2. What ran

| Item | Value |
|---|---|
| Machine | AMD Ryzen 5 7235HS (Zen 3+), single thread, other services running (the host is noisy, ±20 %) |
| Toolchain | clang 18.1.3 `-O2` portable (no `-march`), wasm-ld 18, node v26.8.1 |
| Runs | `scripts/capped pqz-core/rel3/bench.sh r1`: `./build.sh all`, KAT, the `R_REG` / `R_TX` proof hashes, then the timings; raw JSON lines and the build / KAT logs in `pqz-core/rel3/runs/` |
| Parameters | `params/{burn,ds,dr}_params.sage` → `params/pqz_{burn,ds,dr}_params.h` by `params/codegen/run.sh` (LaZer `3330e48`, pinned Sage image, ≈ 1 min each) |
| Statistics | p50 / p99 over the stated number of runs on one machine; the bench's p99 is the 99th-percentile element of the sorted sample |

## 3. The relations

All three are LaZer `tbox` statements over the same ring and modulus as `R_REG` / `R_TX` (q = 2^42 − 215, d = 64,
l = 4), written the way `build_reg` / `build_tx` write theirs: R_q-linear rows as quadratic equations without a
quadratic part, single-coefficient rows as `tbox` evaluation equations ct(X^−i·(…)) = 0, exact ℓ2 norm proofs per
witness block, one binary proof for all bits, and the one-poly approximate ℓ∞ filler LaZer's `tbox` needs.

| | `R_BURN` (pq-zether.md §7.5) | `R_DS` (§7.9, `SENDER_S`) | `R_DR` (§7.9, `RECEIVER_X`, `AUDITOR`) |
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
is outside the range. Each relation has its own ABDLOP keys (`SCAAS-PQZ-ABDLOP-PP-V1 ‖ op`); `REFRESH` shares op 2's,
`AUDITOR` op 5's. With the same `pqz_delta` (1.00366) and MLWE rank floor as `R_REG` / `R_TX`, all three reach the
CTR-PQZ-03 target β ≥ 450 on the first try under lattice-estimator `53da598`, RC.ADPS16
(`params/estimator-e-s1-rel3.txt`) [measured]. The public matrix A is now expanded once and shared by all relations.

**Statements** (`pqz.h`), as pq-zether.md lays them out:

| Op | Statement | Bytes | Read by the relation |
|---|---|---|---|
| 2 `OP_BURN` | header (§7.7, 640 B) ‖ pk_f ‖ T = u_T ‖ v_T ‖ out = u ‖ v_f | 50,048 (= §7.7's burn size) | fee (offset 256) and amount (288), each a be32 word that must be < 2^64; pk_f, T, out |
| 4 `OP_DISCLOSE_SENDER`, 5 `OP_DISCLOSE_RECEIVER` | opTag ‖ proofSystemId ‖ chainId ‖ chainUid ‖ token ‖ registry ‖ entryRef ‖ be32(amount) ‖ u8(kind) ‖ pk ‖ u ‖ v | 33,153 | amount (offset 224, < 2^64), pk, u, v |

Everything else in a statement is only hashed into the transcript (op and the whole statement are absorbed before any
prover message, as for `R_REG` / `R_TX`), so a proof is bound to it. Any coefficient ≥ q or an amount / fee word
≥ 2^64 makes the verifier return 0. Witness encodings follow `R_TX`'s (int8 for CBD(1) vectors, int16 LE for CBD(20)
ones): `R_BURN` s_f ‖ e_f ‖ r ‖ e1 ‖ e2_f ‖ d′ (12,336 B), `R_DS` r ‖ e1 ‖ e2_t (6,176 B), `R_DR` s ‖ e (6,144 B).

## 4. Checks

| Check | Result [measured] |
|---|---|
| Honest proofs verify | every run: native 10 + 200 verifies, wasm 5 + 60 per relation |
| Tampered input rejected | six kinds: one proof bit flipped, random proof bytes, a statement key coefficient changed, proof truncated by one byte, long all-ones tail, a public scalar changed (new kind 5: the burn / disclosure amount, the `R_TX` fee, the `R_REG` message); 126 native + 42 wasm per relation, 0 accepted |
| Arithmetic-layer KAT | 19/19 cases equal to the upstream golden dump |
| `R_REG` / `R_TX` proofs unchanged | `proofs_fnv` native 5 seeds `12ec7452` / `cb562b47`, wasm 3 seeds `3bc7e9b3` / `834d6853`, as on main (P6d-2) |
| Native and wasm give the same proofs | proof lengths per seed equal; hashes over different seed counts in the two runs (10 / 5) |
| Symbol scan (`check_symbols.sh`) | native and wasm objects reference only `memcpy`, `memset`, `__stack_chk_fail`, `__stack_pointer` |

**Arena.** Every relation's ABDLOP keys (A1, A2′, B′) are built at `pqz_init` below the arena base mark and kept. The
three new relations add ≈ 27 MB native / ≈ 21 MB wasm to that base [measured: `R_REG` peak 112 → 139 MB native,
87 → 108 MB wasm; `R_TX` 316 → 344 MB native, 241 → 263 MB wasm]. The arena base after `pqz_init` is 54.5 MB native / 43.3 MB wasm. Init time 110 → 212 ms native,
150 → 292 ms wasm [measured]. The wasm `R_TX` peak, 251 MiB, is now 2 % under the 256 MiB hard limit of CTR-PQZ-18 (it was 10 %), and
every op pays for all five relations' keys [inference]. Ways out, not tried: build a relation's keys at its first use,
keep only the NTT form of the keys (LaZer holds both forms), or derive the keys per call (one `abdlop_keygen`).

## 5. Open questions for the owner

Choices made to keep going; each is easy to change and none changes the measured costs materially [inference].

1. **Statement layouts.** `R_BURN` uses the full §7.7 header (fee and amount as be32 words); the `R_TX` spike still
   uses its shorter E-S1 layout (prefix ‖ keys ‖ T ‖ out ‖ be8(fee)). Moving `R_TX` to §7.7 changes its proofs and
   its `proofs_fnv`, so it was not done here. The disclosure statement's widths are not given in §7.9: chosen are
   32-byte words for chainId, chainUid, token (12 zero bytes ‖ address, as §7.7), registry and entryRef, be32(amount),
   one byte of kind; 33,153 B, so pk starts at an odd offset (257). A be32 kind word (33,184 B) would align it.
2. **What pqz-core checks.** It does not compare the opTag with the op, the kind byte with the op, or the
   proofSystemId (the precompile's prefix check does, §9.1); it reads only the fields its equations need. `REFRESH`
   and `BURN` are one relation under op 2, `RECEIVER_X` and `AUDITOR` one under op 5, told apart by the opTag inside
   the hashed statement.
3. **The disclosure noise bound.** pq-zether.md asks `abs(e′_i) < 2^24`. A binary decomposition proves a range of a
   power-of-two size, so `R_DR` proves e′_i + 2^24 ∈ [0, 2^25), i.e. e′ ∈ [−2^24, 2^24): one value, −2^24, is
   admitted beyond the strict bound. Uniqueness (§4.3) is unaffected: v is a fresh ciphertext with noise
   ≤ B_FRESH = 11,872, so |e − e′| < Δ/2. A bound of 2^14 (still above B_FRESH) would prove 15 bits per coefficient
   instead of 25 and drop the binary witness from 7 polys to 4 [estimate: a few percent of the proof]; that is a spec
   change.
4. **Arena base** (§4): every op now carries 27 MB (native) of keys of relations it does not use.

## 6. Reproduce

```sh
cd pqz-core
params/codegen/run.sh <LaZer 3330e48> params/burn_params.sage > params/pqz_burn_params.h   # also ds, dr
../scripts/capped rel3/bench.sh <label>        # build all, KAT, R_REG / R_TX hashes, timings -> rel3/runs/<label>-*
build/native/pqz_bench 3 10 28                 # the three new relations only (bit mask 4 + 8 + 16)
```
