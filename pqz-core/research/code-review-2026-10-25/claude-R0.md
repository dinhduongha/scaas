# R0 — Claude UltraCode review

Unit: R0, the cryptography design, at commit 008e196c (worktree the frozen review worktree). The review was read-only: nothing was built or run. Each finding below survived a three-vote refutation pass. Duplicate reports are merged, and the final severity follows the majority vote.

## Findings

| id | severity | file:line | claim | evidence | fix |
|---|---|---|---|---|---|
| R0-C1 | **P1** | `pqz-core/pqzl/src/pqz_rel.c:779-786` (row 5, :784); `pqz-core/pqzl/rust/src/rel.rs:541-544`; `pqz-core/pqzh/ligero/src/cs.rs:15, :400-405`; `docs/contracts/pq-zero-knowledge.md:905, :962, :995, :1001`; `docs/research/pqz-anonymity.md:277, :296, :596`; `smartcontracts/evm/src/pqz/PqzCore.sol:374-378` | **Problem.** In R_TXM with the auditor on and two or more legs in one group, all the auditor copies use the same key pk_a, the same group randomness r_g and the same coefficient index. So v_{a,j} − v_{a,k} = Δ(d_j − d_k) + (e2_{a,j} − e2_{a,k}), and the mask cancels.<br>**Impact.** Anyone holding the public statement or the stored blob can read the digit differences of the leg amounts without a key. Against decoys of amount 0, that gives the real recipient and the amount. This breaks both properties op 7 exists for.<br>**Scope.** All four sets, PQZL and PQZH. Under AuditorMode.FULL it happens on every op-7 transfer with M ≥ 2. | **Code, C:** `evaleq (S, e++, T->pka, 2 * K + 2 * K * (j / 4), i, (int)(H.e2f + 1 + j), acc, -cval (T->va[j], i));`. pk_a is parsed once (:704-705).<br>**Code, Rust and PQZH:** rel.rs:544 has the same row. cs.rs pushes `Leg { pk: pka.clone(), v: v_a(j), dig: Some(j), g: j/4 }`.<br>**Spec:** row 5 gives v_{a,j}[i] = (pk_aᵀ r_{g(j)})[i] + e2_{a,j}[i] + Δ·d_{j,i}. CTR-PQZ-19 itself warns: "reusing `r` across two messages leaks `Δ·(m − m')` up to small noise".<br>**Noise vs Δ:** each e2 has an exact l2 bound of 64, so the difference is at most 128 per coefficient (at most 40 for honest CBD(20)). Δ/2 is at least 2^25.<br>**Concrete input:** txm2 with the auditor on. Leg 0 is real with amount a, leg 1 is a decoy. round(centred(v_{a,0}[i] − v_{a,1}[i]) / Δ) = d_{0,i} for i < 16.<br>**No guard:** shape_ok and the TXM table accept aud = 1 with any M. PqzCore.sol:377 reverts auditorOn = 0 under FULL. anonymity.md:296 counts the copies only as repeated hints, and :596 still claims "Amounts stay hidden".<br>**Not verified:** a related variant, the auditor UA as a recipient. | **Rule:** never reuse a (key, r_g) pair for two plaintexts.<br>**(a)** One auditor ciphertext per group: leg t's digits go in coefficients [16t, 16t+16) of pk_aᵀ r_g. This takes 128 hints per group, so re-run DDGR20 per set or cut the group size.<br>**(b)** Fresh r per auditor copy.<br>**Stopgap:** refuse auditorOn = 1 for M ≥ 2.<br>**Also:** forbid auditorUA ∈ {fromUA, recipients}; add a negative vector that subtracts two copies; bump proofSystemId. |
| R0-C2 | P2 | `pqz-core/params/sets/gen_set.py:324, :334`; `pqzl/params/codegen/lnp-tbox-codegen.sage:141, :178`; `pqzl/src/pqz_rel.c:515, :897`; `pqzl/lazer/lnp-tbox.c:1861`; `rust/src/proof/tbox.rs:1047` | **Problem.** For R_REG and R_DR / R_DA, the z4 bimodal rejection is sized for ‖s4‖₂ ≤ 1. Bprime = 1 was entered as an l_inf bound. But s4 = s[0], a CBD(1) secret-key polynomial with ‖s‖₂ ≈ 5.7, so ‖R′s4‖ ≈ 64 against the 18.4 the sizing assumes.<br>**Impact.** The acceptance probability saturates at 1, so z4 is not D_σ4. The covariance is biased along R′s[0], so many proofs of one key leak s[0] up to sign. | **Codegen:** `alpha4 = Bprime`; `stdev4 = gamma4*sqrt(337)*alpha4`.<br>**Headers:** "bound: 1.0", stdev4 99.2, M4 1.0172703. Bimodal is exact only if ‖R′s4‖² ≤ 2·9841·ln M4 ≈ 337, but E‖R′s4‖² = 128·32 = 4096.<br>**Code:** pqz_rel.c:515 has `S->Ds = new_sel (Rq, 1, 2 * K, 0); /* s[0], coefficients in [-1, 1] */`. rej_bimodal (rejection.c:121-155) has no bound check.<br>**Measured:** numerical integration gives SD ≈ 0.036 per proof and variance ×1.075 along R′s[0].<br>**Unaffected:** the debit fillers (s4 = e2, ‖e2‖ ≈ 12.6 ≤ 64).<br>**Not verified:** the finder's estimate of 10^4–10^5 proofs to recover s[0]. | **Bprime:** set it to the l2 bound of s[0] (8 for ternary), giving σ4 ≈ 1.55·2^9, about +96 B per proof.<br>**Checks:** assert in codegen / gen_set that every filler's Bprime is an l2 bound; add an honest-prover check ‖s4‖₂ ≤ Bprime.<br>**Rebuild:** regenerate the headers and bump proofSystemId.<br>**Docs:** fix the "coefficients in [-1, 1]" comments. |
| R0-C3 | P3 (votes P2/P3/P3) | `pqz-core/pqzl/lazer/intvec.c:598-620`; `lnp-quad.c:245, :494`; `rust/src/proof/quad.rs:306`; `rust/src/sv.rs:1743`; `lnp-tbox-codegen.sage:58-59, :159-161, :382`; `params/sets/e_s0_set.py:103-112` | **Problem.** The final challenge c is never rejected above η = 140. Every "knowledge error ≤ 2^-127 under MSIS(…, B = 4η…)" line assumes ‖c‖ ≤ η. But the samplers draw uniformly from all 17^32 σ-stable polynomials, and at least 0.71 % of them exceed η.<br>**Impact.** The stated knowledge error and the MSIS bound do not cover the protocol as implemented. | **Sampler:** 32 coefficients in [−8, 8], mirrored, with no norm test or retry loop.<br>**eta unused:** `params->eta` is never read in pqzl/lazer, pqzl/src or pqzl/rust/src. The only hit is the struct field at lazer-in2.h:424 (`sqrt(l1(o(c)*c)) <= eta XXX sqrt?`).<br>**Measured rate:** every e-s0.txt prints `P(accept) = 0.9929` for the operator norm. LaZer's sqrt-l1 metric is at least the operator norm, so at least 0.71 % of challenges violate it.<br>**Docs:** pqz-parameters-e-s0.md:122-123 itself calls η "the measured 99 % quantile". Earlier reviews listed this only as a residual (D-lazer-fork.md:164, "about 6 sigma").<br>**Not verified:** the worst case ‖c‖₁ ≤ 504 (3.6η) and the finder's β ≈ 395-410 estimate. | **Option 1:** resample c deterministically from (cseed, counter) until √‖σ₋₁(c)c‖₁ ≤ η, identically in the prover and in all verifiers, at the next proofSystemId bump.<br>**Option 2:** recompute B with the worst-case ‖c‖ and re-run e_s1.<br>**Either way:** make e_s0 R4 charge Pr[c ∉ C_η], or count \|C\| without the acceptance factor. |
| R0-C4 | P3 (filed P2; votes P3×3) | `pqz-core/params/sets/n2048-kmax1024/SET.md:17`; `params/sets/README.md:35-37`; `pqzl/params/n-study/enc-n.txt` row 0; `results-n-study.md:120, :208` | **Problem.** n2048-kmax1024 is the set the contracts use today. Its owner exception (β 446.0, primal DDGR20, 80 hints) was granted without the hinted dual_hybrid figure. SET.md says "not measured".<br>**Impact.** The repo's own second model puts that instance at ≈ 442.5 even at a slightly smaller q, which is below 446 and below 450. At the frozen q it is likely about 437-442. | **n-study row 0** (n 2048, K 1,024, q 2^41.691): "450.47 \| 5.53 \| 442.47 / 442.47". results-n-study.md:208 adds "yes by dual_hybrid (−7.5)".<br>**Frozen q** (2^42 − 215): uSVP 476 vs 481 and DDGR20 446.0 vs 450.47, a shift of about −5.<br>**Mitigating:** the "− offset" column is labelled an estimate; it is still ≥ 406 (Kyber-512); the chains are test-only; the set is due to be replaced by n2304. | **Measure:** run dual_hints16k / enc_n at the frozen q.<br>**Record:** put the hinted dual_hybrid figure in SET.md and in the README exception line, and re-present the exception to the owner at that figure. |
| R0-C5 | P3 | `pqz-core/pqzl/params/codegen/lnp-tbox-codegen.sage:368-381` vs `:67, :495`; `pqzl/lazer/lnp-tbox.c:1990, :2691-2740`; `params/sets/e_s0_set.py:119-121` | **Problem 1.** The codegen checks its knowledge-soundness side conditions with Barp built on t = √(1 + ln 2) = 1.301. The verifier accepts ‖z3‖ up to T·16·σ3 with T = 1.64, so the extractable bound is 1.26× what the codegen asserts.<br>**Problem 2.** The upsilon-binary no-wrap check uses √d, but all Z upsilon terms sit in one integer equation, which needs √(Z·d).<br>**Impact.** None today: the conditions still hold with at least 2.9 bits of margin at every set. | **Codegen:** `t = mp.sqrt(1 - mp.log(2 ** (-KAPPA)) / mpf(128))` and `Bz3sqr = floor((T*stdev3*sqrt(256)) ** 2)` with `T = 1.64`.<br>**Verifier:** lnp-tbox.c:1990 rejects only `if (int_gt (l2sqr, params->Bz3sqr))`.<br>**Upsilon:** `__schwartz_zippel_accumulate_upsilon` makes one accumulate2 call with M = 1.<br>**Tightest case:** n2048 txm16, 41·nex·d·Barp′ = 2^39.09 < 2^42. | **Barp:** use 2·√Bz3sqr / √26.<br>**Upsilon:** check q > Barp² + Barp·√(Z·d).<br>**e_s0 part 4:** use the header's Bz3 and the shifted-JL constant.<br>**Then:** re-run e_s0 and codegen; no parameters change. |
| R0-C6 | P3 | `pqz-core/pqzl/src/pqz_fixexp.h:7-10`; `pqzl/lazer/rejection.c:4-9`; `pqzl/lazer/grandom.c:1-7`; `pqzl/rust/src/rand/fixexp.rs`; `docs/contracts/pq-zero-knowledge.md:1453-1454` | **Problem.** The rejection tests and the Gaussian sampler compute acceptance probabilities to about 56-60 bits. The spec says the fixed-point error is "inside the proof's statistical-distance budget", but no budget is defined or argued. The 128-bit variant is a lost "open for P6e" note.<br>**Impact.** The per-proof statistical distance is about 2^-40, not 2^-128. No practical attack follows. | **Header:** "~60-bit acceptance probabilities; … A 2^-128 statistical-distance budget per test needs a 128-bit-mantissa variant (two-limb Horner) - open for P6e."<br>**Code:** Q56 quotients, ln M found to 2^-56, a single 64-bit u, and about 1e5 or more decisions per proof.<br>**Tracking:** the item is in no STATUS.md, decisions.md or spec entry. | **(a)** Implement a two-limb exp with a 128-bit u in C and Rust; or **(b)** state a relative-error / Rényi bound in the spec in place of the sentence.<br>**Either way:** track the item in STATUS.md. |
| R0-C7 | P3 | `pqz-core/params/sets/e_s0_set.py:131-135`; `params/sets/n2304-kmax4096/SET.md:19`; `{n2304,n2560,n2816}/e-s0.txt:47` | **Problem.** e_s0 reports R2 as λ = ⌈128/log₂q⌉ = 3 (137.4 / 150.0 / 162.0 bits), and SET.md copies this. But codegen and every header use λ = 4 (about 183 / 200 / 216 bits).<br>**Gate gap.** The gate never reads the header's λ. A smaller λ would mostly be caught by the R4 knowledge-error check, but not cleanly.<br>**Impact.** None on soundness: the error is conservative. | **e_s0:** `LAM = math.ceil(128 / log2(q))`.<br>**Codegen:** `lmbda = 2 * ceil(KAPPA/(2*log2q1_))` (:150).<br>**Headers:** `pqz_tx_quad_eval = {{ …, 4}}`; e-s1.txt prints "lambda 4".<br>**SET.md:19:** "λ = 3: 137.4 bits".<br>**Prior note:** p16k/results-16k.md:145 already records the difference. | **Gate:** parse λ from the headers; print λ·log₂q; require λ ≥ ⌈128/log₂q⌉ and λ even.<br>**Docs:** correct SET.md. |
| R0-C8 | P3 | `pqz-core/pqzl/params/codegen/lnp-tbox-codegen.sage:161, :382-385`; `params/sets/e_s0_set.py:11, :112, :140-144` | **Problem.** The codegen's eknow charges the challenge term as 1/(2·Csize) = 2^-130, while the repo's e_s0 gate charges 2/\|C\|. The line is upstream LaZer, but upstream's own quad / quad-eval codegens use 2/\|C\|, so this tbox line looks like a typo. | **Codegen:** `eknow = mpf(1)/mpf(2*Csize) + …`. Upstream lnp-quad-codegen.sage:260 uses 2/\|C\|.<br>**Correction to the original finding:** with 2/Csize at 2^129 and prec 512, eknow > 2^-127, so the ceiling prints −126, not −127. With the measured \|C\| = 2^130.79 the sum is ≈ 2^-127.6.<br>**No acceptance impact:** e_s0 already checks 2/\|C\| on the measured \|C\|. | **Formula:** use 2/\|C\| with the measured \|C\|, or keep 2^129 and relax the gate to −126. Do not just swap in 2/Csize: that flips e_s0's `ke <= -127` check to MISS at every set.<br>**Print:** the unrounded log₂(eknow).<br>**Docs:** cite the LNP22 theorem. |
| R0-C9 | P3 | `pqz-core/params/sets/make.sh:58-71` (step_e_s1), `:147`; `params/sets/n2048-kmax1024/set.toml:7` | **Problem.** `make.sh n2048-kmax1024 e_s1` (and `all`) always exits with an error. The frozen set.toml has no kmlwe_min, so `t.get('kmlwe_min')` is None, while e_s1 prints an integer (33).<br>**Record gap.** The frozen set has no e-s1.txt. Its hardness evidence lives only in pqzl/params/estimator-e-s1*.txt (MSIS 452-461, uSVP 470, dual_hybrid 462/464). | **Check:** `if (t.get("pqz_delta"), t.get("kmlwe_min")) != want: sys.exit(...)`. FROZEN is read only in step_codegen.<br>**Disagreement:** gen_set.py:292/304 treats a missing kmlwe_min as LaZer's default. | **make.sh:** treat a missing kmlwe_min as the codegen default (or add `kmlwe_min = 33`, keeping codegen-check identical).<br>**Record:** commit n2048-kmax1024/e-s1.txt. |
| R0-C10 | P3 | `pqz-core/params/sets/n2048-kmax1024/SET.md:16` | **Problem.** The "encryption, no hints" row gives the uSVP cost (2^139.0 / 2^126.1). The cheapest attack is dual_hybrid at 2^136.1 / 2^124.3 (β 466 / 469), which the row leaves out.<br>**Inconsistency.** The other three SET.md files report the minimum over attacks. The 450 bar is still met. | **Estimator:** aprime.txt "today enc": `usvp … β: 476`, `dual_hybrid … β: 466`.<br>**Spec:** state-redesign.md:543 records "2^136.1 / 2^124.3 (dual_hybrid β 466 / 469)".<br>**Siblings:** n2304 / n2560 SET.md:17 and n2816 SET.md:20 use that format. | **Row 16:** "uSVP β 476; full estimate 2^136.1 / 2^124.3 (dual_hybrid β 466 / 469)". |
| R0-C11 | P3 | `docs/contracts/pq-zero-knowledge.md:1484`; `docs/decisions.md:3589` | **Problem.** The Rej1 spec text still says "(to be confirmed in review B, plan Task 11)". Review B confirmed it (F7) and asked for the placeholder to be replaced. The normative spec therefore does not state the ZK assumption for z2. | **Review B:** `pqz-core/research/code-review-2026-10-19/X-review-b-transcript.md:166-180` says "F7 is confirmed. Spec action: replace '(to be confirmed in review B, plan Task 11)' …". That note cites line 1310; the text is now at 1484.<br>**Decisions:** decisions.md:3589 still lists the item as open. | **Spec:** state LNS21 Extended-MLWE, the Wang–Lai–Liu PKC 2024 reduction (ePrint 2023/826), s2 one-time via SHAKE(tag ‖ rnd32 ‖ H(wit) ‖ stmt-hash), and the one-bit hint treated as free as in LNP22 / LaZer.<br>**Decisions:** close :3589. |
| R0-C12 | P3 | `docs/research/pqz-anonymity.md:279, :284-288` | **Problem.** §8.1 still describes one joint e2 block of bound 64·√M and derives the noise from it ("≤ 2·36·164 + 64·√M ≤ 12,064", mint margin 4.07×). The spec and code bound each e2 vector by 64 (owner 2026-10-15).<br>**Impact.** The stale figure is conservative, and the note is non-normative. | **Spec:** CTR-PQZ-26 says "‖e2‖ ≤ 64 for **every** e2 vector".<br>**Code:** pqz_rel.c:553 comment "not one 64 sqrt(M) block".<br>**Specs:** n2304 txm4_params.sage has nine separate 64 blocks. | **§8.1:** switch to per-vector bounds; recompute 2β_sβ_e + 64 per set, or point to worstcase_noise.json. |
| R0-C13 | P3 | `pqz-core/params/sets/n2816-kmax65536/SET.md:30` (PQZH points 1-2); `docs/decisions.md:3644`; `params/sets/README.md:78` | **Problem.** The n2816 no-PQZH write-up says only nested Winograd convolutions remain for a fast 1,789-point DFT, and that "an extension field does not help". It also puts the prover cost at ≈ 10× by costing the radix-1,789 stage naively. Both rest on an incomplete list of options.<br>**Impact.** The verdict (no PQZH at this set) stands. | **Missed route 1:** an exact integer convolution, multi-modular over 4-5 NTT primes of ~30 bits with CRT, the pattern pqz_sv.c already uses (SV_NP = 5).<br>**Missed route 2:** Bluestein over the order-5,232 subgroup of F_{q²}*. This is weaker: it still needs a radix-109 stage.<br>**Cost model:** ligero_params.py:115-116 `fft_cost = n·Σ(r+1)` is a naive per-stage model. | **Wording:** narrow it to "no length-1,788 cyclic NTT in F_q / F_{q²}; CRT or Bluestein routes not explored".<br>**Estimate:** qualify the 10× as a naive-radix figure. The ruling is unchanged. |
| R0-C14 | P3 | `pqz-core/params/sets/n2816-kmax65536/SET.md:30`, `set.toml` (pqzh comment); `README.md:78`; `docs/decisions.md:3644` | **Problem.** The no-PQZH record leaves out the size argument that settles it. In F_q* every subgroup usable as H_k (k ≥ 64) has order divisible by 1,789. At k = 1,789 the test polynomials alone are 253,960 B, so every proof exceeds MAX_PROOF_PQZH (262,144) and the 2^24-transaction ceiling (261,909 B).<br>**Caveat.** This holds for the current F_q-subgroup construction (`ligero.rs:81`), not for a redesign over F_{q²}. | **Layout:** (2(2k−1) + (2k−1−l)) · 4 · EB with EB = 7 (ligero.rs:5-6, :132-134). At k = 1,789, l = 1,661: 9,070 · 28 = 253,960 B.<br>**Lower bound:** with t ≥ 112, every proof is ≥ 266.5 KB.<br>**Finder's model figures:** R_REG 340,879 B and R_TX 377,328 B. | **Record:** add the size bound as the primary reason; keep the prover cost as secondary, corrected per R0-C13. |
| R0-C15 | P3 | `pqz-core/pqzh/ligero/src/set.rs:18-29`; `params/sets/n2304-kmax4096/pqzh_set_fallback.rs`; `params/sets/n2304-kmax4096/rust/set.rs:64`; `pqzh/ligero/src/cs.rs:938-944`; `pqz-core/ffi/src/lib.rs:26-28` | **Problem.** Feature `fallback-retry` swaps the n2304 Ligero preset (n 32,756 / k 817 / t 121, radices 2/19/43/431) but keeps the PQZH proofSystemId labelled `n45752k952t120`. One id then names two incompatible proof systems.<br>**Missing guard.** pqz-ffi const-asserts against `oversize` but has no such guard for `fallback-retry`.<br>**Never tested.** The test that would catch the mismatch has never run under the feature.<br>**Reach.** Only an explicit `--features pqzh-ligero/fallback-retry` build. There is no in-repo feature-unification path: ffi and the wasm crate are separate workspaces. | **set.rs:** `#[cfg(all(feature = "set-n2304-kmax4096", feature = "fallback-retry"))] #[path = ".../pqzh_set_fallback.rs"] mod pqzh;`. PQZH_LABEL is unchanged.<br>**Test:** `ids_are_the_labels_keccak` (added in 91b95a24, 2026-10-23 22:38) is newer than the only fallback record, runs/c8c-fallback-tests.txt (3248c2d9, 19:02).<br>**Mitigation:** the self-test verifies canonical preset-B vectors, so OP_SELFTEST changes, and PqzStartupCheck (PqzPlugin.cs:56-58) refuses start-up with exit 120. | **pqzh-ligero:** export `pub const FALLBACK: bool = cfg!(feature = "fallback-retry")`.<br>**pqz-ffi:** assert `!FALLBACK` next to the OVERSIZE guard.<br>**Label:** give the fallback its own label and id, or const-assert that PQZH_LABEL contains the compiled PRESET_N / K / T.<br>**Tests:** re-run the fallback tests. |
| R0-C16 | P3 (votes P4/P3/P3) | `pqz-core/pqzl/params/codegen/lnp-tbox-codegen.sage:385` vs `:48, :131, :540-542`; `pqzl/params/n-study/e_s1_n.sage:41`; `pqzl/params/e_s1_proof.sage:40`; `pqzl/params/p16k/e_s1_16k.sage:38`; `pqzl/params/z21_msis.sage:36` | **Problem.** The stated MSIS instance uses m1 + m2 columns and leaves out the Z exact-l2 slack polynomials of s1. The real width is m1 + Z + m2 (n2816 tx: 277, not 270).<br>**Impact.** None on β: the optimal attack sub-dimension (~3.4k) is far below either width. This is a wrong label only. | **Codegen:** `abdlop_params … {m1 + Z}, {m2}` and Bound1 uses (m1 + Z), but :385 prints `MSIS({kmsis},{m1+m2},…)`.<br>**Estimator:** e_s1_n.sage passes `m=(c["m1"] + c["m2"]) * 64`. | **Fix:** print and pass m1 + Z + m2; regenerate the header comments and e-s1.txt, or add a note that β is unaffected. |
| R0-C17 | P4 (votes P4×3) | `pqz-core/params/sets/n2304-kmax4096/e-s1.txt` (headers and SUMMARY lines); `params/sets/make.sh:48-56, :62` | **Problem.** The n2304 estimator record names `/params/pa/<rel>_params.sage`, a container path that was never committed. The other sets' records name `/set/`.<br>**Impact.** None on the numbers. Commit d68e0fc8 added the record together with the 14 specs, and those specs equal HEAD apart from comment lines. The kmsis / B / D / γ values match codegen.txt. | **Record:** e-s1.txt:2 reads "== /params/pa/reg_params.sage".<br>**Tree:** `git log --all -- pqz-core/pqzl/params/pa` is empty.<br>**Check gap:** the agreement regex `^=> \S*?(\w+)_params\.sage` ignores the directory part. | **Fix:** re-run `make.sh n2304-kmax4096 e_s1`, or add a provenance line to SET.md. |

## Refuted

| finding | reason |
|---|---|
| none | No finding was refuted. Several were re-graded or corrected: R0-C3, R0-C4, R0-C8, R0-C15, R0-C16, R0-C17. |

## Checked and sound

**Relations prove what the spec says**
- **Balance conservation.** Row 7 telescopes over Z to Σ16^i M_i = d′ + Σ_j d_j + fee (+ the burn amount). See pqz_rel.c:790-814 and cs.rs:831-851. c₋₁ = 0 by construction. c₁₅ = 0 by construction in C (no c₁₅ variable) and by an explicit constraint in PQZH. Every term is < 2^(MBITS+2), far below q.
- **Range.** Binary proofs are over prime F_q. nbin = ⌈bits/64⌉ matches every relation: n2304 R_TX 1011 bits in 16 polys, BURN 947 in 15, DR 432 in 7; n2816 R_TX 1199 in 19, txm16 2159 in 34. Carries in [−64, 2^CBITS − 64) cover honest carries at K_MAX for M ≤ 16. d′ ≥ 0, so no overdraw.
- **Key ownership.**
  - R_REG proves pk = A s + e with exact l2 bounds [β_s, β_e].
  - Row 6 reuses the s_f of row 1.
  - R_DR proves \|e′\| < E < Δ/2.
  - R_DS's amount is unique (\|e2 − e2′\| ≤ 128 < Δ).
  - (s, e) and (r, e1) are unique: λ₁ ≈ 2^27 is far above the ≈ 354 a collision needs.
- **R_REG bound to the UA.**
  - PQZL hashes SHAKE128('SCAAS-PQZ-TRANSCRIPT-V1' ‖ op ‖ be32(len) ‖ stmt).
  - PQZH's Tr::new hashes keccak('SCAAS-PQZH-LIGERO-V1' ‖ op ‖ be32(len) ‖ stmt).
  - Both absorb the message word stmt[64..96] and the proofSystemId (strong Fiat-Shamir).
- **PQZH relations equal PQZL's.** cs.rs encodes the same rows as pqz_rel.c for REG / DS / DR / TX / TX0 / BURN / TXM: groups j/4, auditor copies under pk_a, bit ranges, and an l2 slack ≤ 64 per e2. The leg-to-group mapping matches PqzCore._legOf.
- **R_BURN.** Amount and fee are public and < 2^64 (rd_word64).

**Knowledge soundness at each set**
- **MSIS β ≥ 450.** n2048 452-461, n2304 462-472, n2560 455-468, n2816 454-478. The estimator inputs (kmsis, B, D, γ, q_fixed) match the headers.
- **Hiding MLWE ≥ 450.**
  - uSVP is ≥ 470 at every set.
  - dual_hybrid is 462/464, 465/466, 462/463 and 462/463 at kmlwe 33 / 36 / 39 / 42.
  - The rows formula equals the codegen's simulatability check.
  - s2 is uniform in [−1, 1].
  - Rank 41 at n2816 gives 447/448, the recorded reason for 42.
- **Challenge rounds.**
  - **R2:** λ = 4, so q^-4 ≥ 2^-168. The P6-SZ λ×M matrix is present in C, in pqz_sv.c and in Rust.
  - **R3:** μ is uniform in R_q, so q^-16. q ≡ 9 mod 16 gives exactly 4 factors of X^64 + 1.
  - **R4:** \|C\| = 2^130.79, and 2ω = 16 < q^{1/4}/2 (≥ 724).
  - **JL:** 2^-128.99.
  - β3 / β4 ∈ {±1} are proven.
  - The η gap is reported separately as R0-C3.
- **Fiat-Shamir order.** z3 / z4 go into hz before V3 / V4; tg goes into hash1; h goes into hash2 before μ and c. The B-1 and P6-FS fixes are present.
- **Exactness.** b′² + β_e² < q and 41·N·b′ < q hold for all 14 relations at all four sets (n2816 txm16: 2^40.20 < 2^54).
- **Codegen logs.** All 56 headers were generated with rc = 0 and no stderr, and every recorded hash matches the committed header. err() calls sys.exit(1) when loaded = 0, so every side condition passed.
- **Verifier norm checks.** The checks on z1 and on z21 + (w − γw1), and Bound() = 4η√(B1² + B2²), are consistent with LNP22 (apart from R0-C3 and R0-C5).

**Zero knowledge**
- **Rej1 for z2.** rej_onetime in C (rejection.c:157-171) and Rust (rejection.rs:111-117) rejects iff ⟨z, v⟩ < 0 or the standard test fails, drawing one u per attempt. M2 = exp(1/(2γ2²)). s2 is fresh per proof (hedged ex). Only the spec text is stale (R0-C11).
- **Bimodal z3.**
  - α3 = √(ΣB_i² + (nbin + Z)d).
  - β3 / β4 are fresh per try (the D-3 fix is present).
  - R is Bin₁, drawn from cseed after the commitment.
  - M3 reproduces.
- **z4 in the debit relations and R_DS.** s4 = e2 with ‖e2‖ ≤ 64 = Bprime. Only R_REG / R_DR are wrong (R0-C2).
- **Standard rejection on z1.** T1 covers m1 + Z, and M1 is recomputed after σ1 is rounded.
- **Hints.**
  - The 80 hints per group are 5 keys × 16 coefficients.
  - V_max = var_s·β_e² + var_e·β_s².
  - DDGR20 gives 446.0 / 468.47 / 482.43 / 496.79.
  - Group seeds are domain-separated (pqz_keys.c:173-198), with a per-build salt.
  - Recipients are distinct and ≠ fromUA, and the registry refuses a reused pk.
  - The only same-key, same-r reuse is R0-C1.
- **Prover randomness.** Mask PRF domains are distinct. Prover randomness is hedged in both PQZL and PQZH. With PQZ_REJ_MAX = 1000, a liveness failure has probability ≈ e^-41.

**Encryption**
- **Noise bound.** B_FRESH = 2β_eβ_s + 64 is a Cauchy-Schwarz bound: 11,872 / 13,212 / 14,624 / 15,940.
- **Budget.** K_MAX·B_FRESH ≤ E at every set, even with one unit too many. 2E ≤ Δ, and Δ(2^m − 1) + E < q/2.
- **Mint margin.** 4.14 / 3.08 / 3.36 / 3.08. The rounding tie from n2304's even Δ is unreachable.
- **Digit sums.** 15·K_MAX < 2^MBITS.
- **Unit accounting.** PqzCore.sol:677-697 and PqzStateLib.sol:76-77 cap the noisy units at K_MAX − 1, plus the noise-free trivial unit.
- **Estimator inputs.** CBD(1) / CBD(20), m = n + 48, at each set's own q. No-hint uSVP 476 / 496 / 508 / 520 and dual_hybrid 466 / 487 / 499 / 511. The sample cap does not bind.
- **64-bit margins.** Barrett 2L + 4 ≤ L + 63; SV_NP CRT primes; pqz_dec; the Solidity lazy lanes (273 terms) all fit.

**Ligero**
- **Field and domains.**
  - F_q^4 = F_q[X]/(X^4 − 3) is irreducible at n2048 / n2304 / n2560, giving 2^168 / 2^183.2 / 2^200.
  - 3 generates F_q*.
  - n and k divide q − 1.
  - 3H_n ∩ H_k = ∅.
- **Proven soundness.**
  - Per-query factor max(1 − e/n, (e + 2k − 2)/n) at the unique-decoding radius of RS[n, 2k−1].
  - t = 121 / 120 / 122 gives 128.50 / 128.94 / 129.43 query bits, including 16 bits of PoW. The PoW is verified before the column indices are drawn.
  - Proximity, linear (distinct exponents ≥ 1) and quadratic field terms are all well above the query term.
  - The totals 127.23 / 127.40 / 127.55 are owner-accepted (decisions.md:3569).
- **Zero knowledge.**
  - l = k − t − 1 at every preset: 695 / 831 / 694 (fallback 695, spike-B 832).
  - The blinds u₀, u_lin and u_quad = Z_ζ·h₀ cover w, q and h.
  - Leaves are salted.
  - The fallback's re-prove on proof length depends only on the query indices.
- **Alternative presets.** spike_b is never compiled. The fallback preset is sound in itself; only its id is wrong (R0-C15).

**n2816 no-PQZH reasoning**
- **Arithmetic.** q − 1 = 2³·3·1789·419,563,967,521 and q + 1 = 2·31·109·409·6,517,458,439 are correct. 149 ∤ q − 1, and ord₁₄₉(q) = 148. The fft_cost figures (77.4 M vs 3.7 M) reproduce. The verifier needs no size-n FFT.
- **Fail-closed.** stmt is_pqzh refuses the id, ffi/src/lib.rs:40-42 const-asserts no pqzh feature, and pqzh_none returns false. Only the stated reasoning is incomplete (R0-C13, R0-C14).

**Spec §6 and the research notes**
- **State-redesign spec §6.**
  - The §6.2 security table matches the SET.md rows.
  - The §6.3 sizes match, including op 7 M = 8 at 295,808 B.
  - The §6.4 labels are distinct and encode the parameters.
  - The §6.5 domain factorisations are correct.
- **pqz-core-e-s1.md.** Its constants match the codegen.
- **pqz-tbox-soundness.md §1-§8.** Consistent with the code.
- **aprime.** The ap2816 specs match the n2816 specs.
- **Prior review round.** The 2026-10-19 README was read, and nothing listed there as fixed is re-reported. The η residual from that round became R0-C3. Review B's F7 action was never applied (R0-C11).

## Not covered

- The specialised verifiers (pqz_sv.c), beyond checking that μ, the λ matrix and the B-1 fix are present.
- The C / Rust transcript code beyond the relation rows.
- pqzh cs.rs witness construction (Wit), merkle.rs root_from, and the fft.rs domain code.
- No estimator, DDGR20 or sage script was re-run (read-only review). Figures were taken from the committed logs.
- Extrapolated figures that were not verified: ≈ 438 in R0-C4, β ≈ 395-410 in R0-C3, and 10^4–10^5 proofs in R0-C2.
- The LNP22 knowledge-soundness theorem was not fetched (ePrint returned 403). The constant in R0-C8 rests on the tree's own inconsistency and on upstream's sibling scripts.
- R0-C1's side variants (the auditor UA as a recipient, two UAs registered with one key) were not fully verified.
- Contracts for the non-frozen sets are not wired at this commit, so the Solidity margins there are design headroom only.
- All five critic gaps were covered in the gap round:
  - state-redesign §6.2-§6.5;
  - the per-set codegen logs;
  - pqz-core-e-s1.md, the tbox-soundness note, proof-aprime and the ap* specs;
  - cs.rs equivalence with pqz_rel.c and PQZH Fiat-Shamir;
  - the fallback / spike-B presets and the Ligero field terms.
