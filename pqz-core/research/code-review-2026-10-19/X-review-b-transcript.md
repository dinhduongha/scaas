# Review B (plan `2026-10-19-pqzl-fs3.md` Task 11): the PQZL v3 fix diff and a whole-protocol transcript audit

Reviewer: Claude (fresh reviewer, static), 2026-10-20, main `a61d221`. Diff reviewed: `290806e..361a86b` (merge of
`pqzl-fs3`: Tasks 1–5, review fixes A–E), restricted to `pqz-core/pqzl/{lazer,src,rust/src}`. The line numbers below are
for main `a61d221`. I wrote no forging or cheating-prover tooling (plan global constraint) and ran no tests: the parity
and binding results come from the committed gate `fs9` logs (`pqz-core/runs/gate/fs9-*`).

Severity: P0 = soundness or zero-knowledge break, P1 = serious, P2 = must fix before roll-out, P3 = minor / docs.

## Findings

### B-1 — P0 — V3 / V4 are drawn before the commitment to `g` (`tg`), so the JL consistency rows can be cancelled through `g`

**Locations (all four verifiers and both provers):**
- C generic prover: `lazer/lnp-tbox.c:415–418` (hz = `hash0`), `:484–499` (tg round, `hash` becomes hash1), `:692–712`
  (`__schwartz_zippel_accumulate_z4` / `_z3` get `hash0`, the pre-tg hash), `:3330` (`intmat_urandom (V, …, seed, dom)`),
  `:3561–3580` (row `k` of V added to accumulator `k` with no further challenge: "just add equations that have already
  been multiplied by a challenge"), `:725–745` (`h_i = g_i +` accumulator, only coefficients 0 and d/2 checked).
- C generic verifier: `lazer/lnp-tbox.c:1183–1186`, `:1201–1222` (tg), `:1280–1297` (V on `hash0`).
- C SV: `src/pqz_sv.c:1519–1533` (hash0 = hz), `:1540–1544` (hash1 = H(hash0 ‖ tg)), `:1597` (`g0 = PRG(hash0)`),
  `:1649` (`urandom_mat (V4 / V3, &g0, …)`).
- Rust generic: `rust/src/proof/tbox.rs:1091–1093` / `:781–783` (hash0 = hz), `:1112–1120` / `:789–794` (tg),
  `:715–721` (`sz_z4` / `sz_z3` with `hash0`).
- Rust SV: `rust/src/sv.rs:1316–1318` (hz), `:1328–1332` (hash1), `:1393` (`g0 = &hz`), `:1449–1450` (V on `g0`).

**Trigger.** A cheating prover. Order today (v3): `tA1, tB_` → `ty3, ty4, tbeta` → `R, R'` → `z3, z4` → **V3, V4** →
`tg` → γ → `h` → μ → `t, v, w1` → `c`. V3 / V4 are the Schwartz–Zippel challenge of the 2 × 256 JL equations
`y_i + β·(R s)_i − z_i = 0 (mod q)`: row k of V goes straight into accumulator k. The garbage polynomial `g` that masks the
accumulators is committed in `tg` *after* V is known. The only constraint on `g` is the final relation
`h_i = g_i + acc_i(s)` plus the verifier's check that coefficients 0 and d/2 of `h_i` are zero. Nothing constrains the
coefficients 0 and d/2 of `g` itself (they are zero only because the honest prover samples them so,
`lnp-tbox.c:455–466`).

**Attack sketch (algebra, not run).** Commit `y3, y4, β` honestly with an out-of-range `s3` / `s4`, get `R` from
`cseed`, and send a short `z3` / `z4` that is not `y + β·R·s`. The error vector `e = y + β·R·s − z` is fixed and known.
Derive V from `hz`, compute the known contribution `Σ_i V_k,i·e_i` of the JL rows to the coefficients 0 and d/2 of each
merged accumulator (after `__schwartz_zippel_auto`), and pick `g_i` with coefficients 0 and d/2 equal to minus that
contribution. Then commit `tg`. Every other equation is honest, so its γ-weighted part has coefficients 0 and d/2 equal
to zero whatever γ is. `h_i = g_i + acc_i(s)` passes the coefficient check, and the quadratic proof is honest because
every relation the quad layer checks holds over R_q. The verifier accepts, but `z` no longer witnesses the approximate
range bound on `s3` / `s4`.

**Impact.** This is the same consequence as D-1 / lazer#28 (`docs/research/pqz-tbox-soundness.md` §8.2, first bullet).
The approximate ℓ2 / ℓ∞ bound on `s3` / `s4` is what lets the exact-ℓ2 proofs conclude over Z rather than only mod q.
Without it the per-block noise bounds β_s / β_e of §4.3 are not enforced, and with them neither is the
`(K−1)·B < Δ − E` mint argument (today, and for A', see O3). v3 closes "z after V" but not "g after V". The γ challenges
are fine: they come from hash1, after `tg`. Upstream LaZer has the same order (V from `hash0 = cseed`, before `tg`), so
this extends lazer#28 upstream. Why LNP22 needs this order: in the vanishing-constant-coefficient technique (LNP22 §4.4,
the aggregation of Z_q relations) the prover commits `g` **before** the verifier sends the aggregation challenge, and
soundness is Pr[Σ γ·const(f) = −const(g)] = 1/q over a γ drawn after `g`. LaZer's V is exactly that aggregation
challenge for the JL rows, and it is drawn one move too early. LaZer's own domain numbering supports this reading: the
z4 / z3 domains `M + 2(d−1) + 2 + Z` and `+ 256` continue the hash1 sequence (input equations at 0, β3 at M, β4 at
M + d − 1, υ at M + 2(d−1), binary at +1, the Z exact-ℓ2 domains at +2), as if V were meant to share the γ seed.

**Confirmed / hypothesis.** The order is confirmed in code in all six places listed above. That the order is
exploitable is a hypothesis: the algebra is straightforward and I see no other constraint on `g`'s coefficients 0 and
d/2, but per the plan no cheating prover was built. `L-codex-pqzl-c.md:68` and `N-claude-pqzl-c.md:328` traced the same
chain and accepted it. The binding test `fs_bind` cannot catch this: it checks that the V seeds change with `z3` / `z4`,
not with `tg`.

**Fix (smallest).** Draw V3 / V4 from **hash1** (after `tg`) with the same domains, and keep `R` / `R'` on `cseed`:
- C generic: pass `hash` instead of `hash0` to both `__schwartz_zippel_accumulate_z4` / `_z3` calls, prover (`:697–711`)
  and verifier (`:1284–1296`).
- Rust: in `accumulate_all` (`tbox.rs:715–721`), pass `hash` for V.
- SVs: `urandom_mat (V4 / V3, &g1, …)` (`pqz_sv.c:1649`, `sv.rs:1449–1450`), with the trace hooks moved along.

The domains do not collide: the last hash1 domain is `M + 2(d−1) + 2 + Z − 1`. `hz` stays (hash1 = H(hz ‖ tg) still
binds `z3` / `z4`), and `hash0` becomes unused except as the input of the tg round. This is a transcript change:
`proofSystemId` v4, regenerated vectors and digests, C = Rust parity, `gate fin`. The 7622 roll-out (Task 13) should wait
for it. Add to `fs_bind` (C and Rust, all four verifiers): mutate `tg` by one coefficient (a new test-only mutate
kind) and assert that the kind 2 / 3 (12 / 13) seeds change. Update `pqz-tbox-soundness.md` §8 and the spec's transcript
bullet (B-2).

### B-2 — P3 — The transcript rule and the §8 argument state "absorbed before its challenge", which misses ordering between commitments and challenges

**Locations.** `docs/contracts/pq-zero-knowledge.md:508–515` (transcript bullet); `docs/research/pqz-tbox-soundness.md`
§8.3 ("V3 / V4 and the tg round chain from `hz`", and "LNP22 orders them commitment → R → z → V").

**Trigger / impact.** The rule "every prover message is absorbed before the challenge that checks it" holds in v3 for
every message, yet B-1 still happens: the requirement that matters is that every message a challenge is combined with
(here the masking commitment `tg`) is absorbed before that challenge. The text certified the v3 order as LNP22's, so
B-1 was not looked for. Confirmed (docs).

**Fix.** With B-1: state the rule as "each challenge is derived after every prover message it is combined with,
including the masking commitments (`tg` before V and γ)", and add the B-1 row to §8's table.

### B-3 — P3 — A' derivation: "q ≥ 2^(m+4)·E" is off by one power of two

**Location.** `docs/superpowers/specs/2026-10-20-pqz-state-redesign.md:311–312`.

**Detail.** Uniqueness needs `Δ = ⌊q / 2^(m+2)⌋ ≥ 2E`, that is `q ≳ 2^(m+3)·E = 2^53` (with m = 20, E = 2^30), not
`2^(m+4)·E = 2^54`. Any 54-bit q at or above about 2^53 + 2^22 satisfies the budget. Near 2^53, though, the mint margin
`(Δ − E)/((K−1)B)` would fall to about 1.03×, so q ≈ 2^54 is what gives 3.08×. The conclusion (a 54-bit q) stands; the
inequality as written does not. Confirmed by arithmetic.

**Fix.** Write "`q ≥ 2^(m+3)·E = 2^53` for uniqueness; q ≈ 2^54 for the 3.08× margin".

### B-4 — P3 — A': the completeness headroom of `e_T` is 2.7 % (today 1.38×)

**Location.** Same spec §6.1 (`K·B_FRESH = 1,044,643,840 < 2^30`), `pqz-core/pqzl/params/aprime/aprime.sage`
`budget()`.

**Detail.** `2^30 / (K·B) = 1.027`. Today `2^24 / (K·B) = 1.38`. The budget holds (O3 below), but the headroom is
thin. Raising β_e by one (189 → 190) still fits; raising both bounds by one (B = 2·43·190 + 64 = 16,404,
K·B = 1,075,052,544) exceeds 2^30, and then E = 2^31 fails `2E ≤ Δ` at q ≈ 2^54. Any later re-derivation of the norm
tails (or n > 2816) silently crosses into "q ≈ 2^55". `aprime.sage` checks `K·B ≤ E`, which is the right guard.

**Fix.** Record the 2.7 % headroom in §6.1 next to the 3.08× margin, and keep `K·B ≤ 2^30` as an assertion in the
frozen A' codegen / KAT. The A' `worstcase_noise` KAT (keys at the norm bounds, `K_MAX − 1` aligned credits) must be
regenerated as the completeness check for that edge.

## Prover-message table

Legend: P = prover, V = verifier. "Gen" = generic `tbox` path, "SV" = specialised verifier. Every hash is
`SHAKE128(prev ‖ coder encoding)`. LNP22 order = the interactive order of LNP22 (commit → JL challenge → response →
aggregation challenges → h → μ → quadratic-proof round → c → final response).

| # | Message | Absorbed into (C gen P / V) | C SV | Rust gen P / V | Rust SV | Seeds which challenge | Before? (LNP22) |
|---|---|---|---|---|---|---|---|
| 0 | statement (`op`, `opTag ‖ proofSystemId ‖ …`) | `pqz_stmt_hash` `pqz_rel.c:307`, used at 1406 / 1441 | `hash_stmt` `pqz_sv.c:1491` | `rel.rs:154`, 915 | `sv.rs` `verify_body` arg | all | ✓ first (strong FS) |
| 1 | `tA1`, `tB_` (first l elems of tB) | `abdlop_hashcomm` `abdlop.c:213–233`, from `pqz_rel.c:1048` / `:1078` | `:1492` | `abdlop.rs:32–44`, from `rel.rs:935` / `:900` | `:1292` | R / R' (via cseed) and everything after | ✓ |
| 2 | `ty3`, `ty4`, `tbeta` (tB, the β signs) | P `lnp-tbox.c:1738–1754` (per try, `cseed`); V `_lnp_tbox_check_z34` `:2005–2015`, after the z norm checks | `:1503–1517` (`hashr`) | P `tbox.rs:1000–1008`; V `check_z34` `:274–311` | `:1303–1314` (`hash0`, = cseed) | **R, R'** (`_expand_R_i` / `_expand_Rprime_i` `:2138–2151` on cseed; P `:1772`, `:1811`; Rust `r_times` `:1014`, `:1021`; SV `jl_fold` on `gr` `:1674` / `:1695`, Rust `&hash0` `:1477` / `:1499`) | ✓ |
| 3 | `z3`, `z4` | `_lnp_tbox_hash_z34` `:2048–2097`, called at P `:415–418` / V `:1183–1186` (V after the norm checks) | `:1519–1533` (`hash0` = hz) | `hash_z34` `:317–323`, at P `:1091–1093` / V `:781–783` | `:1316–1318` (`hz`) | **V3, V4** (`hash0` = hz; P / V `:697–711` / `:1284–1296`; SV `:1649`; Rust `:715–721`; Rust SV `:1449–1450`) | ✓ z before V (v3). **✗ V before tg (B-1)** |
| 4 | `tg` (tB) | P `:484–499`; V `:1201–1222` | `:1540–1544` (`hash1`) | P `:1112–1120`; V `:789–794` | `:1328–1332` (`hash1`) | **γ** (input evaluation equations dom 0; β3 / β4 / υ / binary / Z exact-ℓ2 domains; P `:640–690`; SV `g1` `:1746–1751`; Rust `accumulate_all` `:625`, `:633` …; Rust SV `:1552`, `:1556`) | ✓ tg before γ. **✗ tg after V3 / V4 (B-1)** |
| 5 | `h` (`h_i = g_i + acc_i(s)`) | `_lnp_tbox_hash_h` `:2103–2134`, at P `:803` / V `:1345` (V checks coefficients 0 and d/2 first, `:1188–1199`) | `:1545–1548` (`hash2`) | `hash_h` `:327–335`, at P `:1151` / V `:801` | `:1335–1336` (`h2`) | **μ** (`_schwartz_zippel_poly` `lnp-quad-many.c:34`, from `:140` / `:212`; SV `g2` `:1840`; Rust `quad.rs:19–22`, from `:188` / `:70`; Rust SV `:1643`) and, chained, c | ✓ (v3) |
| 6 | `t` (last element of tB: the quadratic garbage commitment), `v`, `w1` | P `lnp-quad.c:216–245` (per try); V recomputes v and w1 (via the hint) and hashes `:477–495` | `:1929–1955` over `hash2` | P `quad.rs:295–306`; V `:129–142` | `:1723–1739` over `g2` | **c** = `poly_urandom_autostable (cseed)` | ✓ |
| 7 | `c` | the final challenge; V recomputes and compares (`lnp-quad.c:494–495`, SV `:1954–1955`, Rust `quad.rs:142–143`, `sv.rs:1739–1740`) | | | | — | ✓ final |
| 8 | `z1`, `z21`, `hint` | not absorbed (final response); norm checks `‖z1‖`, `‖z21‖² + ‖w − γ·w1‖² ≤ B²`, `‖hint‖∞` | | | | — | ✓ final (LNP22: z after c) |

Checked against LNP22's order:
- The commitment comes first, and the β signs are committed (`tbeta`) before R. ✓
- R / R' come after the commitment and before z: they are on cseed, as they must be, since z3 = y3 + β3·R·s3. ✓
- z3 / z4 come before their aggregation challenge V. ✓ (v3)
- **The masking commitment `g` (tg) must come before every aggregation challenge it is combined with: ✓ for γ, ✗ for
  V (B-1).**
- h before μ ✓ (v3); μ before `t, v, w1` ✓ (t and v are built from the μ-combined R2, r1); `t, v, w1` before c ✓;
  the response after c ✓.

The spec's rule "every prover message is absorbed" holds for rows 0–6; `z1`, `z21`, `hint`, `c` are the final response.
The seeds are separate: R on cseed, V on hz, γ on hash1, μ on (hash2, dom 0), c on SHAKE(hash2 ‖ t ‖ v ‖ w1). The v2
γ / μ overlap (review C, settled point 1) is gone.

## F7: Rej1 (`rej_onetime`) and M2

**Code.** C `lazer/rejection.c:157–171`, Rust `rand/rejection.rs` `rej_onetime`, called from `lnp-quad.c:277–279` /
`quad.rs` for `rej2 == 2` with `scM2` and `stdev2sqr`. It rejects iff `⟨z2, c·s2⟩ < 0` OR `rej_standard`, where
`rej_standard` accepts iff `u < exp((‖v‖² − 2⟨z,v⟩)/(2σ2²))/M2` (`rejection.c:101–118`). One `u` is drawn always, so the
rng streams are equal (unit test: same offset, the C and Rust counts identical). The sign is taken branch-free from the
128-bit dot product. ⟨z, v⟩ = 0 is accepted, as in Rej1 ("reject if < 0"). The test runs on the whole `z2 = y2 + c·s2`
(m2·d coefficients), as LaZer's compressed opening does; then the `‖·‖² ≤ B²` check runs. ✓

**M2.** Codegen `params/codegen/lnp-tbox-codegen.sage:241–243`: `σ2 = γ2·η·ν·√(m2·d)`, rounded to a samplable σ, then
γ2 recomputed from the rounded σ2, so `T2 = η·ν·√(m2·d)` and `σ2 = γ2·T2`; `:330–331` `M2 = bim_gamma2M(γ2) =
exp(1/(2γ2²))` (`codegen.sage:263–264`). That is Rej1's constant. LNS21 (PKC 2021, "Shorter lattice-based ZK proofs via
one-time commitments"), restated in LNP22 §2: for `‖v‖ ≤ T`, `σ = γT` and `M = exp(1/(2γ²))`, on `⟨z,v⟩ ≥ 0`,
`exp((‖v‖² − 2⟨z,v⟩)/(2σ²)) ≤ exp(T²/(2σ²)) = M`. So the acceptance ratio never exceeds 1. The output is exactly
D_σ restricted to the half-space `⟨z, v⟩ ≥ 0`, accepted with probability `Pr_{z←D_σ}[⟨z,v⟩ ≥ 0]/M ≈ 1/(2M)`. There is
no 2^-100 slack term, unlike the standard test, which needs `M = exp(x/γ + 1/(2γ²))` (`std_gamma2M`). The measured
0.17737 against `1/(2·M2) = 0.17628` (R_REG, M2 = 2.836, γ2 ≈ 0.693) agrees. **The formula is correct; no parameter
regeneration is needed.** ✓

**Residual (not new).** `‖c·s2‖ ≤ T2` relies on `‖c‖_op ≤ η = 140`, and LaZer's challenge sampler does not enforce it
(`D-lazer-fork.md:164`). For Rej1 an overshoot `‖v‖ > T2` would make the ratio exceed 1 (clamped to accept) and skew the
half-Gaussian. In practice ‖c·s2‖ concentrates near ‖c‖₂·‖s2‖ ≈ ‖s2‖ times a few tens, far below `140·ν·√(m2·d)`
(rough estimate, not measured), so the effect is negligible, but it is heuristic. It is the same caveat as for M1, and
the fix is the one D recommends: reject challenges with √‖σ₋₁(c)·c‖₁ > η.

**Extended-MLWE (one-time commitments).** Rej1 leaks one bit per accepted proof: `z2`'s half-space
`sign⟨z2, c·s2⟩ ≥ 0`. The ZK simulator outputs `z2 ← D_σ2` with the commitment replaced by uniform. Indistinguishability
is LNS21's **Extended-MLWE**: (A, the commitment under `s2`, z, c, sign⟨z, c·s2⟩) against the same tuple with a uniform
commitment. LNS21 reduce it to a leakage version of decision-MLWE against linear functions of the secret. Wang–Lai–Liu
(PKC 2024, ePrint 2023/826) reduce search-MLWE to decision-MLWE with linear leakage, and conclude it stays as hard as
MLWE asymptotically. For concrete parameters it is an assumption: the estimator figures (`kmlwe`, ν = 1) are MLWE
figures, and the one-bit hint is treated as free, as LNP22 / LaZer do. "One-time" means `s2` backs exactly one released
transcript. ✓ in PQZ: `s2 = urandom_bnd(ex[0..32])` with `ex = SHAKE(tag ‖ rnd32 ‖ H(wit) ‖ stmt-hash)`
(`pqz_rel.c:1009–1046`; Rust the same). A new rnd32, witness or statement gives a new `s2`; a repeat gives the
byte-identical proof, so the same bit. Rejected tries reuse `s2`, but only their verdicts (the try count) are observable
(review E, b1). Their acceptance rate is `Pr[⟨z,v⟩ ≥ 0]/M2`, which depends on `v` only through the mass on the
hyperplane `⟨z,v⟩ = 0` (negligible). **F7 is confirmed.** Spec action: replace "(to be confirmed in review B, plan
Task 11)" at `pq-zero-knowledge.md:1310` with this assumption and its two citations.

## O3: the A' noise / digit budget and the 3.08× mint margin

Recomputed independently (Python, deterministic Miller–Rabin):
- q = 2^54 − 327 is prime, q ≡ 9 mod 16, and it is the largest such prime below 2^54 (no prime 2^54 − k with k ≡ 7 mod 16,
  7 ≤ k < 327). LS18 `q^(1/4)/2 = 5,792.6`. ✓
- n = 2816: β_s = ⌈√(1408 + 12.02·√704)⌉ = **42**, β_e = ⌈√(28,160 + 10.15·√549,120)⌉ = **189**,
  B = 2·42·189 + 64 = **15,940**. ✓ The worst-case noise per unit `|⟨e,r⟩| + |⟨s,e1⟩| + |e2| ≤ ‖e‖‖r‖ + ‖s‖‖e1‖ + β_2`
  follows from Cauchy–Schwarz and holds against an adversarial sender because the proof enforces every block's bound
  (P6-L2) — **conditional on B-1 being fixed**, since the exact ℓ2 conclusion rests on the approximate range proof.
- K = 65,536: `K·B = 1,044,643,840 < 2^30 = 1,073,741,824` ✓ (headroom 2.7 %, B-4); reachable `(K−1)·B = 1,044,627,900`
  ✓ (the plain term carries no noise).
- Digits: `15·K = 983,040 < 2^20` ✓, m = 20; e_T ∈ [−2^30, 2^30) is a 31-bit decomposition ✓; `Δ = ⌊q/2^22⌋ = 2^32 − 1`
  ✓; `2E = 2^31 ≤ Δ` ✓ (decoding unique: |e_T| < 2^30 < Δ/2); `Δ·(2^20 − 1) + 2^30 < q/2` ✓ (a wide margin, Δ·2^m ≤ q/4).
- Mint margin `(Δ − E)/((K−1)·B) = 3,221,225,471 / 1,044,627,900 = 3.0836` ✓; today's figure is re-derived as 4.144 ✓.
- The one textual error is "q ≥ 2^(m+4)·E" (B-3).

**Verdict on O3.** The derivation is right, and 3.08× is a sound margin under the same reading as today's 4.14×:
a worst case reachable with keys at the bounds, against the noise needed to shift a digit. It holds only once B-1 is
fixed; until then the norm bounds it assumes are not enforced, today or under A'. I did not check the carry range
(`c_i + 64 ∈ [0, 2^17)`), the R_TX bit counts (1,199 / 1,135), or the estimator / DDGR20 numbers (not rerun).

## Checked and clean

- **The hz round** (C generic `_lnp_tbox_hash_z34`): it encodes centred copies (`fromcrt`, `mod`, `redc`), so the
  callers' `z3` used later by `accumulate_z3` is untouched. The buffer is sized exactly (`coder_grandom3_nbits`, the
  same formula as `coder_enc_grandom3`). On arena exhaustion the coder is skipped and the sticky `pqz_err` fails both
  verify (`pqz_rel.c:1447`) and prove. The verifier hashes only after the norm checks.
- **The SV z3 ‖ z4 round:** `buf ≥ proof_len + 1 + 64`, and the re-encoding of the decoded, norm-checked values equals
  the proof's bit range (bijective decoder), so it fits. In-place reduction of `F.h` is acceptable (not read again;
  `hc` holds the centred copy).
- **The h round:** urandom3 of h in [0, q) (`redp` on a copy in generic C, `reduced(x, false)` in Rust, in place in the
  SV). It is injective; h's length is fixed per relation.
- **The R / R' versus V seed split** (`rseed` parameter): the prover's `R·s` (cseed) and the verifier's JL rows
  (cseed / `gr` / `&hash0` in the Rust SV) agree; the trace kinds 2 / 3 / 4 / 5 and 12 / 13 / 15 are in place.
- **μ and the final round on hash2** in all four verifiers (`pqz_sv.c:1840`, `:1950`; `sv.rs:1643`, `:1738`); γ stays
  on hash1 (`:1746–1751`). The plan's Review Focus item 5 is satisfied.
- **D-3:** the β3 / β4 bits are `8 − nrbits` for nrbits ∈ {8, 6, 4, 2} (bits 0–7, each used once), a refill below 2,
  `rbits` wiped at the end (C `explicit_bzero`, Rust `wipe`); C and Rust are identical.
- **D-2 / `rej_onetime`:** see F7; the rng parity holds even when the sign test rejects.
- **`proofSystemId`:** bound through the statement prefix (`opTag ‖ proofSystemId`), which the statement hash absorbs
  first, so v2 / v3 transcripts cannot be confused even without the transcript change.
- **Review E annotations in the diff** (`pqz_ct_public_*`, `PQZ_CT_PUBLIC` on verdicts and transcript messages): they
  declassify only messages that are hashed or sent and accept / reject bits; there is no control-flow change in the
  verifier.

## Not checked

- Running tests or gates: I relied on `pqz-core/runs/gate/fs9-*` (PASS on `e85d8b4`) for C = Rust parity, the binding
  tests and the vectors.
- The LNP22 / LNS21 / Wang–Lai–Liu texts were checked from memory and a web search, not against the PDFs line by line.
  In particular, the exact figure and lemma numbers cited for LNP22 §4.4 and the Rej1 lemma should be confirmed by the
  external audit.
- Exploitability of B-1 in practice: no cheating prover was built (plan constraint).
- The PRG stream separation inside `intmat_urandom` / `urandom_q` / `_brandom` for the different domains (I read the
  domain numbers, not the stream construction).
- A': the carry ranges, the R_TX / R_BURN / R_DR bit layouts, the lattice-estimator and DDGR20 figures, the codegen
  proof sizes (`proof-aprime.txt`).
- The non-transcript parts of the 1,366-line source diff (`dcompress.c`, `int.c`, `lazer-in2.h`, `rel.rs`,
  `pqz_rel.c` witness code, `ct.rs`), reviewed by review E and Task 10.
