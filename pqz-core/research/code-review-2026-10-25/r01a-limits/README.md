# R0 fix part a: limit check of the new R_TXM shapes (2026-10-25)

Before any core change of part a (brief `task-r01a-brief.md`, "report any limit hit — stop if one would need raising"),
the shapes that the owner's group sizes change were checked against the limits. `s_aud` = 2 / 3 / 4 / 4 (n2048 /
n2304 / n2560 / n2816) with the auditor on, 4 without. Only the audited R_TXM shapes of n2048-kmax1024 and n2304-kmax4096
change: G = ⌈M / s_aud⌉ gives n2048 M = 4 → G 2, M = 8 → G 4; n2304 M = 4 → G 2, M = 8 → G 3. n2560 / n2816 keep G = 1 / 1 / 2.
Also checked: R_REG / R_DR with `Bprime = 8` (R0-C2).

Files: `mkspecs.py` (the changed PQZL specs from `gen_set.py`'s text, `specs/<set>/`), `es1.sh` (make.sh's e_s1 on
them, pinned Sage image, `--memory 5g --cpus 2`) → `es1-<set>.txt`, `pqzh_bound.py` (PQZH bound and precompile input
per shape: `pqzh/ligero/ligero_params.py`'s layout model, which equals the crate's exact bound on every built shape, with
the group count changed), `pqzh_search.py` (a preset search for the audited M = 4 shape).

## PQZL: within the limits [measured: e_s1 / codegen]

| Set | Spec | m1 | MSIS β | MLWE uSVP β | dual_hybrid β | codegen proof size (expected) | vs `MAX_PROOF_PQZL` 98,304 |
|---|---|---|---|---|---|---|---|
| n2048-kmax1024 | txm4 (G 2) | 219 | 459 | 470 | 462 / 464 | ~60,898 B | fits |
| n2048-kmax1024 | txm8 (G 4) | 359 | 453 | 470 | 462 / 464 | ~89,098 B | fits (≈ 9 KB margin on the expected size) |
| n2048-kmax1024 | reg (Bprime 8) | 64 | 452 | 470 | 462 / 464 | ~29,284 B | fits |
| n2048-kmax1024 | dr (Bprime 8) | 71 | 461 | 470 | 462 / 464 | ~30,246 B | fits |
| n2304-kmax4096 | txm4 (G 2) | 244 | 464 | 472 | 465 / 466 | ~66,750 B | fits |
| n2304-kmax4096 | txm8 (G 3) | 328 | 466 | 472 | 465 / 466 | ~83,984 B | fits |
| n2304-kmax4096 | reg (Bprime 8) | 72 | 467 | 472 | 465 / 466 | ~31,578 B (today ~31,482) | fits |
| n2304-kmax4096 | dr (Bprime 8) | 79 | 465 | 472 | 465 / 466 | ~32,810 B (today ~32,714) | fits |

All ≥ 450 at the set's `pqz_delta` / `kmlwe_min` (unchanged). PQZL precompile input, largest new statement: n2048
audited M = 8, G = 4: 248,704 + 98,304 + 5 = 347,013 ≤ `MAX_INPUT` 393,216; n2304 audited M = 8, G = 3: 260,992 + 98,304 +
5 = 359,301 ≤ 524,288.

## PQZH: audited R_TXM M = 4 exceeds the limits at n2048 and n2304 [model = crate bound]

| Set | Shape | G | proof bound (today, G = 1) | `MAX_PROOF_PQZH` | precompile input | `MAX_INPUT` |
|---|---|---|---|---|---|---|
| n2048-kmax1024 | R_TXM M = 4, auditor on | 2 | **279,756** (236,196) | 262,144 | **429,137** | 393,216 |
| n2304-kmax4096 | R_TXM M = 4, auditor on | 2 | **296,248** (253,048) | 262,144 | 464,061 | 524,288 |
| n2560-kmax16384 | R_TXM M = 4, auditor on | 1 | 305,120 (unchanged) | 327,680 | 470,885 | 524,288 |

Every other PQZH shape keeps G and its bound (PQZH builds M ∈ {1, 2, 4}; M = 2 stays G = 1 at both sets). No preset
closes the gap: the smallest audited M = 4 bound over the set's radices (proven regime, query soundness ≥ the preset's)
is 277,628 B at n2048 (n 65,512, k 817, t 117) and 294,782 B at n2304 (n 111,112, k 1,292, t 117), both above 262,144.

Options (an owner decision; part a stopped here): (1) PQZH does not build audited R_TXM M = 4 at n2048 / n2304
(PQZH built legs with the auditor {1, 2} there; PQZL keeps {1, 2, 4, 8}; no limit changes); (2) raise
`MAX_PROOF_PQZH` at n2304 to ≥ 296,248 (input fits 512 KiB) and at n2048 to ≥ 279,756 together with `MAX_INPUT` ≥
429,137 (a per-set limit raise, CTR-PQZ-10's option C).
